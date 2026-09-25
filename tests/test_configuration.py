from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from analyzer import DEFAULT_MODEL
from configuration import load_configuration
from test_analyzer import FakeHTTP, SOURCE, wire_response


def write_secrets(directory, text, encoding="utf-8"):
    path = directory / ".streamlit" / "secrets.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding)
    return path


def test_project_secrets_work_from_another_working_directory(tmp_path, monkeypatch):
    project = tmp_path / "AI Code Analyzer"
    write_secrets(project, 'GEMINI_API_KEY = "project-test-key"\n')
    monkeypatch.chdir(tmp_path)
    settings, warnings = load_configuration(project, environ={}, user_dir=tmp_path / "user")
    assert settings == {"GEMINI_API_KEY": "project-test-key", "GEMINI_MODEL": DEFAULT_MODEL}
    assert warnings == []


def test_environment_then_project_then_user_precedence(tmp_path):
    project, user = tmp_path / "project", tmp_path / "user"
    write_secrets(user, 'GEMINI_API_KEY = "user-key"\nGEMINI_MODEL = "user-model"\n')
    write_secrets(project, 'GEMINI_API_KEY = "project-key"\n')
    settings, warnings = load_configuration(project, environ={"GEMINI_MODEL": "env-model"}, user_dir=user)
    assert settings == {"GEMINI_API_KEY": "project-key", "GEMINI_MODEL": "env-model"}
    assert warnings == []
    settings, _ = load_configuration(project, environ={"GEMINI_API_KEY": "env-key"}, user_dir=user)
    assert settings["GEMINI_API_KEY"] == "env-key"


def test_missing_files_are_silent_and_new_file_is_picked_up(tmp_path):
    project, user = tmp_path / "project", tmp_path / "user"
    settings, warnings = load_configuration(project, environ={}, user_dir=user)
    assert settings["GEMINI_API_KEY"] == "" and warnings == []
    write_secrets(project, 'GEMINI_API_KEY = "new-key"\n', encoding="utf-8-sig")
    settings, warnings = load_configuration(project, environ={}, user_dir=user)
    assert settings["GEMINI_API_KEY"] == "new-key" and warnings == []


def test_invalid_toml_shows_sanitized_warning(tmp_path):
    write_secrets(tmp_path, 'GEMINI_API_KEY = "PRIVATE_VALUE\n')
    settings, warnings = load_configuration(tmp_path, environ={}, user_dir=tmp_path / "user")
    assert settings["GEMINI_API_KEY"] == ""
    assert len(warnings) == 1 and "Cannot parse" in warnings[0]
    assert "PRIVATE_VALUE" not in warnings[0]


def test_invalid_value_type_and_unreadable_file(tmp_path):
    write_secrets(tmp_path, 'GEMINI_API_KEY = 1234\n')
    _, warnings = load_configuration(tmp_path, environ={}, user_dir=tmp_path / "user")
    assert len(warnings) == 1 and "quoted text" in warnings[0]
    with patch.object(Path, "read_text", side_effect=PermissionError("PRIVATE_VALUE")):
        _, warnings = load_configuration(tmp_path, environ={}, user_dir=tmp_path)
    assert len(warnings) == 1 and "Cannot read" in warnings[0]
    assert "PRIVATE_VALUE" not in warnings[0]


def test_ui_uses_app_local_key_without_repeated_missing_secrets_errors(tmp_path, monkeypatch):
    project = tmp_path / "AI Code Analyzer"
    write_secrets(project, 'GEMINI_API_KEY = "project-test-key"\n')
    source_app = Path(__file__).resolve().parents[1] / "app.py"
    test_app = project / "app.py"
    test_app.write_text(source_app.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.chdir(tmp_path)
    with patch("analyzer.request.urlopen", return_value=FakeHTTP(wire_response())) as opener:
        app = AppTest.from_file(str(test_app), default_timeout=30).run()
        assert not app.exception and not app.error
        app.text_area(key="code_input").set_value(SOURCE)
        app.button(key="analyze_button").click().run()
        assert not app.exception and not app.error
    assert opener.call_args.args[0].get_header("X-goog-api-key") == "project-test-key"
    assert app.session_state["analysis"]["result"]["metadata"]["provider_status"] == "Completed"
