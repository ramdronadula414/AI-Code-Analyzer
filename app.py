"""AI Code Analyzer v2 — detection, defensive corrections and clear reports."""

from pathlib import Path

import streamlit as st

from analyzer import (LANGUAGES, MAX_CODE_CHARS, VERSION, analyze_code,
                      corrected_filename, detect_language, input_fingerprint)
from configuration import load_configuration
from file_processing import ALLOWED_EXTENSIONS, process_file
from reports import build_docx_bytes, build_json_bytes, build_pdf_bytes, build_report_text

st.set_page_config(page_title="AI Code Analyzer v2", page_icon="🛡️", layout="wide")


def inject_custom_styles():
    st.markdown("""
    <style>
    .stApp { background: #080b12; color: #f5f5f5; }
    .block-container { max-width: 1440px; padding-top: 2rem; }
    .hero { background: linear-gradient(125deg,#151b29,#1e1018); border: 1px solid #683039;
        border-radius: 20px; padding: 30px 34px; margin-bottom: 24px; }
    .hero h1 { color: #fff; font-size: clamp(2rem,4vw,3.6rem); letter-spacing: -0.04em; margin: 8px 0; }
    .hero p { color: #d0d4de; max-width: 850px; font-size: 1.1rem; line-height: 1.6; }
    .version { color: #ff8e95; font-size: .85rem; letter-spacing: .14em; font-weight: 700; }
    .hero-steps { display:flex; flex-wrap:wrap; gap:12px; margin-top:22px; }
    .hero-steps span { border:1px solid #633039; border-radius:9px; padding:9px 14px; color:#f9d4d7; }
    h2, h3 { color: #ff7b85 !important; }
    [data-testid="stMetric"] { padding:16px; border:1px solid #45303c; border-radius:12px; background:#141925; }
    [data-testid="stMetricValue"] { font-size:1.5rem; }
    .stTextArea textarea { background:#0e1420; color:#edf0f7; font-family:monospace; }
    .stButton button[kind="primary"] { background:#bf2738; color:white; border:1px solid #eb5a68; }
    .stButton button, .stDownloadButton button { min-height:44px; border-radius:10px; }
    [data-testid="stExpander"] { background:#101623; }
    [data-testid="stTabs"] { margin-top:24px; }
    @media(max-width:640px) { .hero { padding:20px; } .block-container { padding:1rem; } }
    </style>
    """, unsafe_allow_html=True)


def code_language(language):
    return {"C++": "cpp", "C#": "csharp", "Shell": "bash", "Batch": "batch",
            "Unknown": "text"}.get(language, language.lower())


def show_list(items):
    for index, item in enumerate(items, 1):
        st.text(f"{index}. {item}")


def render_findings(findings, *, prefix=""):
    if not findings:
        st.info("No findings reported in this review. This does not prove the code is safe.")
        return
    st.dataframe([{"ID": f["id"], "Severity": f["severity"], "Category": f["category"],
                   "Finding": f["title"], "Lines": f"{f['line_start']}–{f['line_end']}",
                   "Evidence": f["evidence_status"],
                   "Remediation": f.get("remediation_status", "Manual review required")} for f in findings],
                 use_container_width=True, hide_index=True)
    for f in findings:
        # Titles are model-supplied: do not interpolate them into Markdown/HTML labels.
        with st.expander(f"{prefix}{f['id']} · {f['severity']} · Lines {f['line_start']}–{f['line_end']}"):
            st.text(f["title"])
            st.caption(f"{f['category']} · {f['confidence']} confidence estimate · {f['origin']} · {f['cwe'] or 'No CWE specified'}")
            if f["evidence_status"] != "Matched to source":
                st.warning("This AI excerpt does not match the cited source lines. Verify the finding manually.")
            st.markdown("**Source evidence**")
            st.code(f["evidence"], language="text", line_numbers=False)
            for label, key in [("Why it was flagged", "explanation"), ("Potential impact", "impact"), ("Recommended fix", "recommendation")]:
                st.markdown(f"**{label}**")
                st.text(f[key])


def render_result(result, source):
    meta, correction = result["metadata"], result["correction"]
    st.subheader("Security review")
    st.caption(f"{meta['filename']} · {meta['analyzed_at']} · {meta['duration_seconds']} seconds")
    if meta["provider_status"] != "Completed":
        st.warning(f"{meta['provider_status']}: {meta['provider_message']}")
    first, second, third, fourth = st.columns(4)
    first.metric("Assessment", result["classification"])
    second.metric("Highest severity", result["severity"])
    third.metric("Findings", len(result["findings"]))
    fourth.metric("Correction", correction["status"].replace("_", " ").title())
    st.text(result["summary"])
    st.caption("Static review. Severity and confidence are estimates; no code has been executed.")
    report_tab, correction_tab, export_tab = st.tabs(["Detection report", "Corrected code", "Download report"])
    with report_tab:
        render_findings(result["findings"])
        if result["local_cross_check"]:
            st.markdown("### Local cross-check")
            st.caption("Additional rule matches for manual review; these are not confirmed malware and are not included in the AI finding count.")
            render_findings(result["local_cross_check"], prefix="Local ")
        st.markdown("### Recommended actions")
        show_list(result["recommendations"] or ["Review the code and its trust boundaries and test the application."])
        with st.expander("Scope and limitations"):
            show_list(result["limitations"])
            st.text(f"Engine: {meta['engine']}\nModel: {meta['model']}\nSource SHA-256: {meta['source_sha256']}")
    with correction_tab:
        st.text(correction["reason"])
        if correction["code"]:
            st.warning("Proposed correction — review the changes and test legitimate behavior before use.")
            before, after = st.columns(2)
            with before:
                st.markdown("**Original source**")
                st.code(source, language=code_language(result["language"]), line_numbers=True)
            with after:
                st.markdown("**Proposed corrected source**")
                st.code(correction["code"], language=code_language(result["language"]), line_numbers=True)
            st.download_button("Download corrected source", correction["code"].encode("utf-8"),
                               file_name=corrected_filename(meta["filename"], result["language"]),
                               mime="text/plain", key="download_corrected")
            st.markdown("### What changed")
            show_list([f"{', '.join(c['finding_ids'])}: {c['description']}" for c in correction["changes"]])
            with st.expander("Compare changes (unified diff)", expanded=True):
                st.code(correction["diff"], language="diff")
            st.markdown("### Checks on the proposed code")
            st.text(f"Syntax: {correction['validation']['status']} — {correction['validation']['detail']}")
            st.caption("Runtime tests were not run. A syntax pass is not a security verdict.")
            if correction["rescan_findings"]:
                st.warning(f"The local rescan still found {len(correction['rescan_findings'])} indicator(s).")
                render_findings(correction["rescan_findings"], prefix="Rescan ")
            else:
                st.info("No local rules matched the proposed code. Manual security review is still required.")
        elif correction["status"] == "rejected":
            st.error("The generated replacement failed validation. No corrected-code download is offered.")
        elif correction["status"] == "not_needed":
            st.info("No replacement was proposed because this review found no issue requiring a code change.")
        else:
            st.info("No corrected source is available for this review. See the reason above and recommended actions.")
        if correction["remaining_risks"]:
            st.markdown("### Remaining risks and setup")
            show_list(correction["remaining_risks"])
        st.markdown("### Suggested tests — not executed")
        show_list(correction["suggested_tests"] or ["Test normal behavior, invalid inputs and each security finding in an isolated environment."])
    with export_tab:
        st.write("Download the complete findings, evidence, fix explanations, validation status and proposed code.")
        st.caption("Reports can contain source code and credentials from your input. Share them carefully.")
        if st.button("Prepare report downloads", key="prepare_reports"):
            with st.spinner("Preparing reports…"):
                # Per-session storage only. Do not globally cache source code or reports.
                st.session_state["exports"] = {
                    "TXT": (build_report_text(result).encode("utf-8"), "text/plain", "txt"),
                    "JSON": (build_json_bytes(result), "application/json", "json"),
                }
                for label, builder, mime, suffix in [
                    ("PDF", build_pdf_bytes, "application/pdf", "pdf"),
                    ("Word", build_docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
                ]:
                    try:
                        st.session_state["exports"][label] = (builder(result), mime, suffix)
                    except Exception:
                        st.warning(f"{label} export could not be created. TXT and JSON reports remain available.")
        exports = st.session_state.get("exports", {})
        if exports:
            columns = st.columns(len(exports))
            for column, (label, (data, mime, suffix)) in zip(columns, exports.items()):
                column.download_button(f"Download {label}", data, file_name=f"AI_Code_Analyzer_v2_Report.{suffix}",
                                       mime=mime, key=f"download_{suffix}")


def main():
    inject_custom_styles()
    configuration, configuration_warnings = load_configuration(Path(__file__).resolve().parent)
    api_key = configuration["GEMINI_API_KEY"]
    model = configuration["GEMINI_MODEL"]
    st.markdown("""
    <div class="hero"><div class="version">SECURITY WORKSPACE · VERSION 2.0</div>
    <h1>AI Code Analyzer</h1>
    <p>Understand suspicious behavior and vulnerabilities, inspect proposed corrections, and export a clear security report.</p>
    <div class="hero-steps"><span>01 · Detect</span><span>02 · Explain</span><span>03 · Correct</span><span>04 · Review</span></div></div>
    """, unsafe_allow_html=True)
    left, right = st.columns([2, 1], gap="large")
    source, filename, source_kind, input_error = "", "pasted_code", "source", ""
    with left:
        st.subheader("Source code")
        input_mode = st.radio("Input method", ["Paste code", "Upload file"], horizontal=True, key="input_mode")
        if input_mode == "Paste code":
            source = st.text_area("Paste source code", height=340, key="code_input", placeholder="Paste a complete source file here…")
        else:
            uploaded = st.file_uploader("Upload source or a document", type=sorted(x[1:] for x in ALLOWED_EXTENSIONS), key="file_upload")
            if uploaded is not None:
                filename = uploaded.name
                try:
                    source, source_kind = process_file(uploaded.getvalue(), filename)
                except ValueError as exc:
                    input_error = str(exc)
                    st.error(input_error)
        st.caption(f"One complete file · up to {MAX_CODE_CHARS:,} characters · 5 MB upload limit")
    with right:
        st.subheader("Review options")
        for message in configuration_warnings:
            st.warning(message)
        engine = st.radio("Analysis engine", ["Gemini AI + local checks", "Local checks only"], key="engine")
        language = st.selectbox("Source language", ["Auto"] + list(LANGUAGES), key="language")
        generate = st.checkbox("Generate corrected source", value=True, key="generate_correction")
        if engine.startswith("Gemini"):
            if api_key:
                st.caption("Gemini key configured. Connection is checked when you analyze.")
            else:
                st.info("GEMINI_API_KEY is not configured. Local checks work; corrected-code generation needs Gemini.")
            st.text(f"Model: {model}")
            st.caption("Clicking Analyze sends the selected source and filename to Google's Gemini API. Remove secrets before submitting.")
        else:
            st.caption("Local mode keeps source on this app server. It provides limited indicators; it does not generate corrections.")
        if source_kind != "source":
            st.info("Document/notebook input is analyzed as extracted text. Upload a complete source file for corrected-code generation.")
    if source:
        with st.expander("Preview the exact input with line numbers", expanded=input_mode == "Upload file"):
            st.code(source, language=code_language(detect_language(filename, source, language)), line_numbers=True)
    fingerprint = input_fingerprint(source, filename, language, generate, engine + model + source_kind)
    if st.button("Analyze & generate report", type="primary", key="analyze_button", disabled=bool(input_error)):
        st.session_state.pop("analysis", None)
        st.session_state.pop("exports", None)
        try:
            with st.spinner("Reviewing source and checking any proposed correction…"):
                result = analyze_code(source, filename, language=language, api_key=api_key, model=model,
                                      correction_requested=generate, source_kind=source_kind,
                                      use_ai=engine.startswith("Gemini"))
            st.session_state["analysis"] = {"result": result, "source": source, "fingerprint": fingerprint}
        except ValueError as exc:
            st.error(str(exc))
        except Exception:
            st.error("The review could not be completed. Try again with a smaller source file. No correction has been accepted.")
    saved = st.session_state.get("analysis")
    if saved:
        if saved["fingerprint"] != fingerprint or input_error:
            st.warning("The input or review options changed. Analyze again to generate a report for the current input.")
        else:
            render_result(saved["result"], saved["source"])
        if st.button("Clear report", key="clear_report"):
            st.session_state.pop("analysis", None)
            st.session_state.pop("exports", None)
            st.rerun()
    st.divider()
    st.caption(f"AI Code Analyzer {VERSION} · Files and results are held in this session's memory. The app does not intentionally save uploads to disk. Gemini requests are subject to Google's data policies. No submitted or generated code is executed.")


if __name__ == "__main__":
    main()
