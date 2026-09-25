import copy
import json
from urllib import error
from unittest.mock import patch

import pytest

from analyzer import (MAX_CODE_CHARS, analyze_code, corrected_filename, gemini_review,
                      input_fingerprint, local_findings, validate_response)

SOURCE = 'import os\nname = input("Name: ")\nos.system("echo " + name)\n'
FIXED = 'name = input("Name: ")\nprint(name)\n'


def response_fixture():
    return {
        "classification": "Vulnerable", "summary": "Untrusted input enters a shell command; use direct output instead.",
        "language": "Python", "findings": [{
            "id": "F001", "title": "Command injection", "category": "Vulnerability", "severity": "High",
            "confidence": "High", "line_start": 3, "line_end": 3, "evidence": 'os.system("echo " + name)',
            "explanation": "The input is concatenated into a shell command.", "impact": "Untrusted input could execute another command.",
            "recommendation": "Print the name without using a shell.", "cwe": "CWE-78",
        }], "recommendations": ["Remove the shell boundary."], "limitations": ["External context is unavailable."],
        "correction": {
            "status": "proposed", "reason": "Replaced the shell with direct output.", "code": FIXED,
            "changes": [{"finding_ids": ["F001"], "description": "Use print for the name and remove the unused os import."}],
            "remaining_risks": ["Check whether callers expect shell echo formatting."],
            "suggested_tests": ["Test ordinary names and shell metacharacters; they should print literally."],
        },
    }


class FakeHTTP:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, limit):
        return json.dumps(self.payload).encode()[:limit]


def wire_response(review=None, finish="STOP"):
    return {"candidates": [{"finishReason": finish, "content": {"parts": [{"text": json.dumps(review or response_fixture())}]}}]}


def test_full_review_sends_key_in_header_and_separates_untrusted_source():
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response())) as opener:
        result = analyze_code(SOURCE, "example.py", api_key="test-key")
    req = opener.call_args.args[0]
    assert "test-key" not in req.full_url
    assert req.get_header("X-goog-api-key") == "test-key"
    payload = json.loads(req.data)
    assert "UNTRUSTED DATA" in payload["systemInstruction"]["parts"][0]["text"]
    assert json.loads(payload["contents"][0]["parts"][0]["text"])["source"] == SOURCE
    assert "tools" not in payload
    assert opener.call_args.kwargs["timeout"] == 90
    assert result["metadata"]["provider_status"] == "Completed"
    assert result["findings"][0]["evidence_status"] == "Matched to source"
    assert result["correction"]["code"] == FIXED
    assert result["correction"]["validation"]["status"] == "Passed"
    assert result["correction"]["rescan_findings"] == []
    assert "-os.system" in result["correction"]["diff"]
    assert result["local_cross_check"]


@pytest.mark.parametrize("source", [
    'import requests\nrequests.post("https://example.com", json={"status": "ok"})\n',
    'from cryptography.fernet import Fernet\nvalue = "crypt and upload"\n',
    'import sqlite3\ncursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n',
    'import os\n# eval(user_input)\nexample = "os.system(command)"\n',
    '\"password = \\\'test123\\\'\"\n',
    'x = f"eval(hello)"\n',
])
def test_benign_patterns_do_not_become_malware(source):
    result = analyze_code(source, "sample.py", use_ai=False)
    assert result["classification"] == "No findings"
    assert not result["findings"]
    assert not result["correction"]["code"]


def test_fallback_has_lines_and_no_fabricated_correction():
    result = analyze_code(SOURCE, "example.py")
    assert result["metadata"]["provider_status"] == "Not configured"
    assert result["classification"] == "Suspicious"
    assert result["findings"][0]["line_start"] == 3
    assert result["correction"]["status"] == "unavailable"
    assert not result["correction"]["code"]


@pytest.mark.parametrize("code,status", [(401, "Authentication error"), (403, "Permission error"),
                                         (404, "Model unavailable"), (429, "Rate limited"), (500, "API error")])
def test_provider_failure_is_sanitized_and_keeps_local_review(code, status):
    failure = error.HTTPError("https://example.invalid/?key=SECRET", code, "SECRET", {}, None)
    with patch("analyzer.request.urlopen", side_effect=failure):
        result = analyze_code(SOURCE, "sample.py", api_key="SECRET")
    assert result["metadata"]["provider_status"] == status
    assert "SECRET" not in json.dumps(result)
    assert result["findings"]
    assert result["correction"]["status"] == "unavailable"


@pytest.mark.parametrize("exc,status", [(TimeoutError(), "Timeout"), (error.URLError("SECRET"), "Network error")])
def test_transport_errors(exc, status):
    with patch("analyzer.request.urlopen", side_effect=exc):
        result = analyze_code(SOURCE, "sample.py", api_key="SECRET")
    assert result["metadata"]["provider_status"] == status
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize("payload,status", [
    (wire_response(finish="MAX_TOKENS"), "Truncated response"),
    ({"candidates": []}, "Blocked or empty response"),
    ({"candidates": [{"finishReason": "SAFETY"}]}, "Blocked or incomplete response"),
    ({"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "bad json"}]}}]}, "Invalid response"),
    (wire_response({"classification": "SAFE"}), "Invalid response"),
])
def test_incomplete_ai_reports_are_not_accepted(payload, status):
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(payload)):
        result = analyze_code(SOURCE, "sample.py", api_key="test-key")
    assert result["metadata"]["provider_status"] == status
    assert not result["correction"]["code"]


@pytest.mark.parametrize("mutation", [
    lambda r: r["findings"][0].update(line_start="3"),
    lambda r: r.update(classification="No findings"),
    lambda r: r["correction"]["changes"][0].update(finding_ids=["F999"]),
    lambda r: r["correction"].update(status="not_needed"),
    lambda r: r["findings"][0].update(evidence=""),
])
def test_semantically_broken_response_rejected(mutation):
    data = response_fixture()
    mutation(data)
    with pytest.raises(ValueError):
        validate_response(data, SOURCE)


def test_unmatched_ai_evidence_remains_clearly_unverified():
    raw = response_fixture()
    raw["findings"][0]["line_start"] = 900
    raw["findings"][0]["line_end"] = 900
    raw["classification"] = "Malicious"
    result = validate_response(raw, SOURCE)
    assert result["findings"][0]["evidence_status"] == "Unverified source reference"
    assert result["findings"][0]["confidence"] == "Low"
    assert result["classification"] == "Suspicious"


@pytest.mark.parametrize("replacement", ["def bad(:", SOURCE, "```python\nprint(1)\n```", "# rest of code unchanged\n"])
def test_bad_corrections_withheld_but_analysis_preserved(replacement):
    raw = response_fixture()
    raw["correction"]["code"] = replacement
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response(raw))):
        result = analyze_code(SOURCE, "sample.py", api_key="test-key")
    assert result["findings"][0]["title"] == "Command injection"
    assert result["correction"]["status"] == "rejected"
    assert not result["correction"]["code"]


@pytest.mark.parametrize("kwargs", [{"source_kind": "document"}, {"source_kind": "notebook"}, {"correction_requested": False}])
def test_corrections_disabled_even_if_model_ignores_request(kwargs):
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response())) as opener:
        result = analyze_code(SOURCE, "sample.py", api_key="test-key", **kwargs)
    sent = json.loads(json.loads(opener.call_args.args[0].data)["contents"][0]["parts"][0]["text"])
    assert sent["correction_requested"] is False
    assert not result["correction"]["code"]


def test_remaining_indicators_are_visible_without_claiming_fixed():
    raw = response_fixture()
    raw["correction"]["code"] = SOURCE + "# Changed comment only\n"
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response(raw))):
        result = analyze_code(SOURCE, "sample.py", api_key="test-key")
    assert result["correction"]["rescan_findings"]
    assert result["correction"]["status"] == "proposed"


def test_input_limit_rejects_entire_request_before_api_call():
    with patch("analyzer.request.urlopen") as opener:
        for source in ("", " " * 10, "a" * (MAX_CODE_CHARS + 1), "a\x00b"):
            with pytest.raises(ValueError):
                analyze_code(source, api_key="test-key")
    opener.assert_not_called()


def test_local_only_never_calls_provider_with_configured_key():
    with patch("analyzer.request.urlopen") as opener:
        analyze_code(SOURCE, "sample.py", api_key="configured", use_ai=False)
    opener.assert_not_called()


def test_no_execution_of_submitted_or_corrected_source(tmp_path):
    sentinel = tmp_path / "must_not_exist"
    payload = f'open({str(sentinel)!r}, "w").write("executed")\n'
    raw = response_fixture()
    raw["correction"]["code"] = payload
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response(raw))):
        analyze_code(payload, "sample.py", api_key="test-key")
    assert not sentinel.exists()


def test_safe_download_name_and_input_identity():
    assert corrected_filename("../../evil.pdf", "Python") == "evil_corrected.py"
    assert corrected_filename(r"C:\temp\foo.py", "Python") == "foo_corrected.py"
    assert input_fingerprint("a", "a.py", "Auto", True, "AI") != input_fingerprint("b", "a.py", "Auto", True, "AI")
