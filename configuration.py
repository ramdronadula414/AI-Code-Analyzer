"""Load configuration relative to the app, independently of the launch directory."""

import os
from pathlib import Path
import tomllib

from analyzer import DEFAULT_MODEL


def load_configuration(app_dir, *, environ=None, user_dir=None):
    """Environment > app-local secrets > user secrets; never print secret values.

    Parse directly instead of probing st.secrets, which renders missing-file errors
    before raising on Streamlit 1.41.1. Read once per app rerun so new/edited local
    files take effect without a stale secrets cache.
    """
    environ = os.environ if environ is None else environ
    user_dir = Path.home() if user_dir is None else Path(user_dir)
    paths = [user_dir / ".streamlit" / "secrets.toml",
             Path(app_dir).resolve() / ".streamlit" / "secrets.toml"]
    settings = {"GEMINI_API_KEY": "", "GEMINI_MODEL": DEFAULT_MODEL}
    warnings = []
    for path in dict.fromkeys(paths):
        try:
            # utf-8-sig also accepts a BOM written by Windows text editors.
            values = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            continue
        except (tomllib.TOMLDecodeError, UnicodeError):
            warnings.append(f"Cannot parse {path}. Use UTF-8 TOML with quoted values for GEMINI_API_KEY and GEMINI_MODEL.")
            continue
        except OSError:
            warnings.append(f"Cannot read {path}. Check the file permissions and that secrets.toml is a file.")
            continue
        for name in settings:
            if name not in values:
                continue
            if not isinstance(values[name], str):
                warnings.append(f"{name} in {path} must be a quoted text value.")
            elif values[name].strip():
                settings[name] = values[name].strip()
    for name in settings:
        value = environ.get(name, "").strip()
        if value:
            settings[name] = value
    return settings, warnings
