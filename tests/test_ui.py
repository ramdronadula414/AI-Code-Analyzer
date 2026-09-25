from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from test_analyzer import FakeHTTP, SOURCE, FIXED, wire_response


def test_local_ui_report_survives_rerun_and_invalidates_on_edit(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    app = AppTest.from_file("app.py", default_timeout=30).run()
    assert not app.exception
    app.radio(key="engine").set_value("Local checks only")
    app.text_area(key="code_input").set_value(SOURCE)
    app.button(key="analyze_button").click().run()
    assert not app.exception
    assert app.session_state["analysis"]["result"]["classification"] == "Suspicious"
    app.button(key="prepare_reports").click().run()
    assert not app.exception
    assert set(app.session_state["exports"]) == {"TXT", "JSON", "PDF", "Word"}
    assert len(app.get("download_button")) == 4
    app.run()
    assert app.session_state["analysis"]
    app.text_area(key="code_input").set_value("print('changed')").run()
    assert any("input or review options changed" in warning.value for warning in app.warning)
    assert len(app.get("download_button")) == 0
    app.button(key="clear_report").click().run()
    assert not app.exception
    assert "analysis" not in app.session_state


def test_ai_ui_shows_fix_diff_and_downloads_without_second_api_call(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    app = AppTest.from_file("app.py", default_timeout=30).run()
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response())) as opener:
        app.text_area(key="code_input").set_value(SOURCE)
        app.button(key="analyze_button").click().run()
        assert not app.exception
        assert app.session_state["analysis"]["result"]["correction"]["code"] == FIXED
        assert any("-os.system" in block.value for block in app.code)
        assert len(app.get("download_button")) == 1
        app.button(key="prepare_reports").click().run()
        assert not app.exception
        assert len(app.get("download_button")) == 5
        assert opener.call_count == 1


def test_empty_input_shows_error_not_old_report(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    app = AppTest.from_file("app.py", default_timeout=30).run()
    app.button(key="analyze_button").click().run()
    assert not app.exception
    assert any("non-empty" in e.value for e in app.error)
    assert "analysis" not in app.session_state
