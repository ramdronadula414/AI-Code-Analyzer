# AI Code Analyzer v2

A Streamlit security reviewer for source code. It explains vulnerabilities and suspicious behavior, proposes defensive corrections, and exports a complete detection-and-correction report.

## What's new in 2.0

- **Corrected source:** a complete proposed replacement, original/corrected comparison, unified diff, finding-linked change log and source download.
- **Clear findings:** category, severity, confidence estimate, exact source excerpt, line numbers, potential impact, CWE where applicable, recommended action and remediation status.
- **Validation visibility:** source-evidence matching, Python/JSON syntax checks, local rescan of proposed code, remaining risks and suggested tests. Unsupported languages explicitly say syntax was not checked.
- **Complete reports:** TXT, JSON, paginated PDF and Word exports include findings, validation, proposed code and diff. Reports no longer stop at the end of one PDF page.
- **Reliable failure states:** missing key, HTTP errors, quota limits, timeouts, blocked/truncated output and malformed AI responses fall back to clearly labelled local indicators. The fallback never invents corrected code.
- **Session persistence:** results and downloads survive Streamlit reruns. Editing source or review options hides outdated downloads until a new analysis completes.
- **Honest assessment:** ordinary networking, encryption, imports and file writes are no longer classified as malware simply for existing. Fixed confidence/latency marketing numbers were removed.

## Run locally

Use Python 3.11 or 3.12. From the repository directory:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Local checks work without an API key. For AI analysis and corrected-code generation, configure `GEMINI_API_KEY` in your hosting environment or create `.streamlit/secrets.toml` locally:

```toml
GEMINI_API_KEY = "your-key-here"
GEMINI_MODEL = "gemini-2.5-flash"
```

Never commit the real key. Configuration precedence is: environment variables, `.streamlit/secrets.toml` beside `app.py`, then `.streamlit/secrets.toml` in your user home directory. The app reads these TOML files directly, independently of the terminal's current directory; creating or editing the file takes effect on the next rerun. A missing file is optional and does not render Streamlit's repeated "No secrets found" errors. `.env` files are **not** loaded automatically. End users of a hosted app do not need their own key when the host has configured one.

For example, when `app.py` is in `D:\projects\AI Code Analyzer`, save the key at `D:\projects\AI Code Analyzer\.streamlit\secrets.toml` (not `secrets.toml.txt`). Windows UTF-8 files with a BOM are supported. `GEMINI_MODEL` is optional. Restart with:

```powershell
Set-Location "D:\projects\AI Code Analyzer"
python -m streamlit run app.py
```

`GEMINI_MODEL` defaults to `gemini-2.5-flash` for continuity with the existing project. Set it to a structured-output-capable model available to your Google account if that model is unavailable. Model access and quotas depend on the account. The app sends requests directly to the Gemini REST API with the key in a header; it no longer depends on the old `google-generativeai` package.

API references: [generateContent](https://ai.google.dev/api/generate-content), [structured output](https://ai.google.dev/gemini-api/docs/generate-content/structured-output), [model availability](https://ai.google.dev/gemini-api/docs/deprecations).

## Use the v2 workflow

1. Choose **Paste code** or **Upload file**. Only the selected input is analyzed.
2. Select the source language when auto-detection is uncertain, and choose **Gemini AI + local checks** for corrections.
3. Leave **Generate corrected source** enabled and click **Analyze & generate report**.
4. In **Detection report**, inspect each finding's evidence, impact, fix recommendation and remediation status.
5. In **Corrected code**, review the replacement, changes, validation results and remaining indicators before downloading it.
6. In **Download report**, click **Prepare report downloads** and choose TXT, JSON, PDF or Word.

Proposed corrections preserve legitimate behavior where possible and remove/disable harmful behavior. If the intended safe behavior is unclear, the model is instructed to request manual review instead of repairing malware functionality. Corrections are never applied to your original files automatically.

### Correction statuses

| Status | Meaning |
| --- | --- |
| Proposed | Replacement supplied; review and application tests are still required. |
| Not needed | The AI review found no issue requiring a code change; this is not proof of safety. |
| Manual review | Safe intent/context is unclear or cited evidence could not be verified. |
| Unavailable | Local mode, failed/unconfigured AI, disabled correction or extracted document/notebook input. |
| Rejected | Replacement failed syntax validation, was unchanged, or contained detected incomplete-output markers. |

## Inputs and limits

Supported source extensions: Python, JavaScript/JSX, TypeScript/TSX, Java, C/C++ headers and sources, C#, PHP, HTML, CSS, SQL, shell, batch, TXT, JSON, XML and YAML. Source uploads must use UTF-8.

PDF, DOCX and Jupyter notebooks support **analysis of extracted text only**. Line references refer to the extracted text, not PDF page positions or notebook cells. Upload the complete source file separately to request corrected code. Scanned PDFs without text need OCR outside this application.

- One file per review; at most 60,000 source characters and 5 MB per upload.
- Oversized input is rejected, not silently truncated.
- PDFs are limited to 100 pages; expanded DOCX contents to 20 MB.
- Up to 50 findings per engine. The local rule set is intentionally small and not a complete malware scanner.
- PDF uses built-in fonts and shows unsupported Unicode as `[U+XXXX]`; TXT, JSON, Word and the source download retain Unicode characters. Use the source download to reuse corrected code.

## Privacy and verification boundaries

- Submitted and generated code are **never executed** by the app. No shell, package installer or runtime test tool is exposed to the model.
- Gemini mode sends the selected source and filename to Google. Remove secrets first. Local-only mode performs no Gemini request, even when a server key exists.
- Uploads and reports are held in the current app session's memory; there is no app database, shared result cache or intentional disk persistence. Hosting infrastructure and Google have their own data policies.
- Provider exceptions are sanitized so API keys and raw provider payloads are not displayed in reports.
- Source text, filename, comments and strings are treated as untrusted model input; these instructions reduce prompt-injection risk but do not guarantee immunity.
- Evidence matching verifies that an excerpt exists at the cited location; it does not prove the model's interpretation.
- A syntax pass and a clean local rescan do not prove correctness, security or functional equivalence. Dependencies, other files, deployment settings and runtime behavior are outside this review.
- The tool can miss issues and report false positives. Confidence is a qualitative estimate, not a measured accuracy or malware probability.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests cover conservative fallback behavior, real request construction with simulated provider responses, malformed/truncated/refused output, sanitized API errors, evidence verification, correction validation, extraction, report pagination and Streamlit input/report/download workflows. Tests never execute submitted samples or contact Gemini. A real configured-key smoke test is still needed on the target deployment.

## Existing Render service

After the v2 branch is merged/deployed, keep the service as a Python Streamlit web service:

- Build: `pip install -r requirements.txt`
- Start: `streamlit run app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`
- Health check: `/_stcore/health`
- Environment: `GEMINI_API_KEY`; optionally `GEMINI_MODEL`

This update does not change your Render configuration or automatically deploy a new service.

## Project layout

| File | Responsibility |
| --- | --- |
| `app.py` | Streamlit interface, configuration and per-session result/download state |
| `configuration.py` | Environment and app-relative/user TOML configuration loading |
| `analyzer.py` | Gemini request, validated review contract, local rules and correction checks |
| `file_processing.py` | Bounded source/document extraction |
| `reports.py` | Shared report content and TXT/JSON/PDF/Word serialization |
| `tests/` | Automated regression and Streamlit workflow tests |
