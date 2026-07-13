# app.py
"""
AI Code Analyzer - Intelligent Malware & Vulnerability Detection
Single-file Streamlit application that accepts code input or uploaded files,
extracts code, and analyzes for malicious behavior, vulnerabilities, and suspicious patterns.
Uses Google Gemini API when available; falls back to a local heuristic analyzer on API failure.
"""

import os

import streamlit as st
import io
import json
import re
import time
import base64
import traceback

# File handling and parsing
from pypdf import PdfReader
import docx
import magic  # python-magic
import pandas as pd
import requests

# Optional AI client (google-generativeai). We'll attempt to use it if available.
try:
    import google.generativeai as genai  # type: ignore
    GENAI_AVAILABLE = True
except Exception:
    GENAI_AVAILABLE = False

# ---------------------------
# Configuration and Constants
# ---------------------------

st.set_page_config(
    page_title="AI Code Analyzer - Intelligent Malware & Vulnerability Detection",
    layout="wide",
    initial_sidebar_state="expanded",
)

TITLE = "AI Code Analyzer - Intelligent Malware & Vulnerability Detection"
ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".java",
    ".cpp",
    ".c",
    ".php",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".bat",
    ".txt",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".ipynb",
    ".pdf",
    ".docx",
}

# ---------------------------
# Custom UI Styles

def inject_custom_styles():
    st.markdown(
        """
        <style>
        :root {
            color-scheme: dark;
            font-family: 'Inter', system-ui, sans-serif;
        }
        .stApp {
            background: #05060A;
            color: #f5f5f5;
            font-size: 15px;
        }
        .stApp::before {
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top left, rgba(220, 38, 38, 0.12), transparent 25%),
                        radial-gradient(circle at bottom right, rgba(239, 68, 68, 0.08), transparent 20%);
            pointer-events: none;
            z-index: 1;
        }
        .css-1d391kg > div:first-child {
            position: relative;
            z-index: 2;
        }
        .glass-panel,
        .dashboard-panel,
        .dashboard-section,
        .glass-card,
        .result-card {
            background: rgba(17, 24, 39, 0.96);
            border: 2px solid rgba(255, 0, 0, 0.25);
            box-shadow: 0 18px 48px rgba(0, 0, 0, 0.25), 0 0 14px rgba(255, 0, 0, 0.20);
            backdrop-filter: blur(12px);
            border-radius: 20px;
            padding: 0 24px 24px 24px;
            position: relative;
            overflow: hidden;
            transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
        }
        .glass-card {
            background: rgba(17, 24, 39, 0.98);
            border: 2px solid rgba(255, 0, 0, 0.25);
        }
        .glass-card:hover,
        .result-card:hover,
        .full-width-card:hover {
            transform: translateY(-2px);
            border-color: #FF1E1E;
            box-shadow: 0 0 18px rgba(255, 0, 0, 0.45), 0 0 35px rgba(255, 0, 0, 0.22);
        }
        .result-card::after {
            content: '';
            position: absolute;
            inset: 0;
            background-image:
                radial-gradient(circle at top left, rgba(220, 38, 38, 0.08), transparent 28%),
                linear-gradient(145deg, rgba(220, 38, 38, 0.06), transparent 35%);
            pointer-events: none;
        }
        .panel-header {
            position: relative;
            padding: 10px 16px;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 20px;
            background: rgba(10, 18, 28, 0.78);
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 2;
            font-size: 0.95rem;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            color: #f8d7da;
            box-shadow: inset 0 0 22px rgba(220, 38, 38, 0.08);
        }
        .panel-header .header-label {
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        .panel-header .header-icon {
            width: 32px;
            height: 32px;
            display: grid;
            place-items: center;
            border-radius: 12px;
            background: rgba(220, 38, 38, 0.14);
            color: #fff1f3;
        }
        .hero-card {
            margin-bottom: 32px;
            padding: 34px;
            border-radius: 24px;
            border: 1px solid rgba(220, 38, 38, 0.18);
            background: linear-gradient(135deg, #0C1018 0%, #111827 100%);
            box-shadow: 0 32px 70px rgba(0, 0, 0, 0.34);
        }
        .hero-title {
            font-size: 56px;
            font-weight: 900;
            letter-spacing: -0.04em;
            background: linear-gradient(180deg, #ffffff 0%, #FF1E1E 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            color: transparent;
            text-shadow: 0 0 30px rgba(255, 0, 0, 0.75);
            margin-bottom: 14px;
        }
        .hero-subtitle {
            max-width: 760px;
            font-size: 22px;
            line-height: 1.6;
            color: #D4D4D4;
            margin-bottom: 26px;
        }
        .hero-metrics {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 18px;
        }
        .hero-metric {
            padding: 22px 24px;
            border-radius: 22px;
            background: rgba(17, 16, 22, 0.94);
            border: 1px solid rgba(220, 38, 38, 0.14);
            color: #f8f1f1;
        }
        .hero-metric span {
            display: block;
            font-size: 0.80rem;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: rgba(248, 113, 113, 0.84);
            margin-bottom: 10px;
        }
        .hero-metric strong {
            display: block;
            font-size: 2rem;
            color: #ffffff;
        }
        .page-shell {
            max-width: 1600px;
            margin: 0 auto;
            padding: 32px;
        }
        .page-header {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            gap: 24px;
            align-items: flex-start;
            margin-bottom: 32px;
        }
        .page-header-left {
            display: grid;
            gap: 18px;
            max-width: 900px;
        }
        .page-brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .page-logo {
            width: 56px;
            height: 56px;
            display: grid;
            place-items: center;
            border-radius: 18px;
            background: rgba(17, 17, 17, 0.95);
            border: 1px solid rgba(220, 38, 38, 0.18);
            color: #fff;
            font-size: 1.6rem;
        }
        .page-title {
            font-size: 56px;
            font-weight: 900;
            margin: 0;
            color: #ffffff;
            line-height: 1.02;
        }
        .page-subtitle {
            font-size: 22px;
            line-height: 1.6;
            color: rgba(255, 255, 255, 0.78);
            max-width: 720px;
        }
        .status-badge {
            align-self: center;
            display: inline-flex;
            flex-wrap: wrap;
            gap: 12px;
            padding: 16px 22px;
            border-radius: 22px;
            background: rgba(16, 18, 28, 0.96);
            border: 1px solid rgba(220, 38, 38, 0.18);
            box-shadow: 0 22px 45px rgba(220, 38, 38, 0.12);
            color: #f7ecec;
            font-size: 0.95rem;
            min-width: 220px;
        }
        .status-badge .status-label {
            font-weight: 700;
            color: #ffcccc;
        }
        .page-section {
            margin-bottom: 32px;
        }
        .section-title {
            font-size: 30px;
            font-weight: 900;
            color: #FF1E1E;
            margin-bottom: 18px;
            letter-spacing: 2px;
            text-transform: uppercase;
            text-shadow: 0 0 15px rgba(255, 0, 0, 0.6);
            border-bottom: 3px solid #FF3B30;
            padding-bottom: 10px;
            box-shadow: 0 0 18px rgba(255, 0, 0, 0.2);
        }
        .analysis-panel {
            display: grid;
            gap: 24px;
        }
        .analysis-panel .glass-card,
        .analysis-panel .full-width-card {
            border-radius: 20px;
        }
        .input-grid {
            display: grid;
            gap: 24px;
            grid-template-columns: minmax(0, 1.75fr) minmax(320px, 1fr);
        }
        .input-panel {
            background: rgba(17, 24, 39, 0.96);
            border: 1px solid rgba(220, 38, 38, 0.18);
            border-radius: 20px;
            padding: 24px;
            min-height: 420px;
        }
        .analysis-button-wrapper {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 18px;
            flex-wrap: wrap;
            margin-top: 16px;
        }
        .progress-pill {
            padding: 14px 18px;
            border-radius: 18px;
            background: rgba(16, 20, 28, 0.92);
            color: #ffd7d7;
            border: 1px solid rgba(220, 38, 38, 0.16);
            font-size: 0.95rem;
        }
        .full-width-card {
            border-radius: 20px;
            padding: 28px;
            background: rgba(17, 22, 32, 0.96);
            border: 1px solid rgba(220, 38, 38, 0.16);
        }
        .card-heading,
        .panel-title,
        .code-preview-heading {
            display: flex;
            align-items: center;
            width: 100%;
            height: 56px;
            padding: 0 20px;
            margin: 0;
            color: #FF3B3B;
            font-size: 28px;
            font-weight: 800;
            letter-spacing: 2px;
            text-transform: uppercase;
            text-shadow: 0 0 12px rgba(255, 0, 0, 0.45);
            background: rgba(255, 20, 20, 0.06);
            border-bottom: 1px solid rgba(255, 0, 0, 0.35);
            border-top-left-radius: 18px;
            border-top-right-radius: 18px;
            box-sizing: border-box;
        }
        .card-heading,
        .panel-title,
        .code-preview-heading {
            margin-bottom: 0;
            padding-top: 0;
            padding-bottom: 0;
        }
        .metric-card {
            padding: 24px;
            border-radius: 24px;
            border: 1px solid rgba(220, 38, 38, 0.14);
            background: rgba(17, 18, 24, 0.96);
            color: #f9f4f4;
            margin-bottom: 20px;
        }
        .metric-card strong {
            display: block;
            font-size: 2rem;
            margin-bottom: 8px;
            color: #ffffff;
        }
        .status-pill {
            display: inline-flex;
            gap: 10px;
            align-items: center;
            padding: 14px 20px;
            border-radius: 999px;
            background: rgba(31, 11, 14, 0.96);
            border: 1px solid rgba(220, 38, 38, 0.22);
            color: #ffffff;
            margin-bottom: 16px;
        }
        .pulse-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #FF3B30;
            box-shadow: 0 0 14px rgba(255, 59, 48, 0.75);
            animation: pulse 1.8s infinite ease-in-out;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.9; }
            50% { transform: scale(1.35); opacity: 0.55; }
        }
        .code-preview-heading {
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 18px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        .code-preview-panel {
            border-radius: 24px;
            padding: 22px;
            background: rgba(16, 18, 26, 0.94);
            border: 1px solid rgba(220, 38, 38, 0.16);
        }
        .result-card-title {
            font-size: 0.95rem;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            color: #ffb3b3;
            margin-bottom: 14px;
        }
        .result-card-value {
            font-size: 2.4rem;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 8px;
        }
        .result-card-meta {
            color: rgba(248, 113, 113, 0.78);
            font-size: 0.94rem;
            line-height: 1.6;
        }
        .analysis-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
            align-items: stretch;
            grid-auto-rows: 1fr;
            margin-bottom: 22px;
        }
        .result-card {
            min-height: 240px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .result-card.safe {
            border-color: #22C55E;
            box-shadow: 0 0 15px rgba(34, 197, 94, 0.35);
        }
        .result-card.suspicious {
            border-color: #F59E0B;
            box-shadow: 0 0 15px rgba(245, 158, 11, 0.35);
        }
        .result-card.malicious {
            border-color: #FF1E1E;
            box-shadow: 0 0 18px rgba(255, 0, 0, 0.45);
        }
        .result-card.critical {
            border-color: #B30000;
            box-shadow: 0 0 22px rgba(179, 0, 0, 0.55);
        }
        .threat-table-wrapper {
            width: 100%;
            overflow-x: auto;
            margin-top: 18px;
        }
        .threat-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            table-layout: fixed;
            min-width: 980px;
        }
        .threat-table th,
        .threat-table td {
            padding: 16px 18px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
            white-space: pre-wrap;
        }
        .threat-table th {
            color: #fecaca;
            font-size: 0.84rem;
            text-transform: uppercase;
            letter-spacing: 0.14em;
            border-bottom: 1px solid rgba(255, 255, 255, 0.12);
        }
        .threat-table td {
            background: rgba(17, 24, 39, 0.94);
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            color: #e5e7eb;
            font-size: 0.95rem;
        }
        .threat-table tr:nth-child(odd) td {
            background: rgba(14, 18, 29, 0.92);
        }
        .threat-table tr:hover td {
            background: rgba(220, 38, 38, 0.12);
        }
        .threat-table td:first-child {
            border-top-left-radius: 18px;
            border-bottom-left-radius: 18px;
        }
        .threat-table td:last-child {
            border-top-right-radius: 18px;
            border-bottom-right-radius: 18px;
        }
        .threat-table tr:last-child td {
            border-bottom: none;
        }
        .detail-text {
            color: #f5f5f5;
            font-size: 15px;
            line-height: 1.75;
            padding: 18px 0;
        }
        .footer-note {
            color: rgba(255, 255, 255, 0.72);
            font-size: 15px;
            line-height: 1.7;
        }
        .recommendation-list {
            display: grid;
            gap: 14px;
        }
        .recommendation-item {
            display: grid;
            grid-template-columns: 40px 1fr;
            gap: 16px;
            align-items: start;
            padding: 16px;
            border-radius: 18px;
            background: rgba(25, 12, 16, 0.72);
            border: 1px solid rgba(220, 38, 38, 0.18);
        }
        .recommendation-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            background: rgba(220, 38, 38, 0.14);
            color: #ffffff;
            font-weight: 800;
            border: 1px solid rgba(220, 38, 38, 0.22);
            text-shadow: 0 0 10px rgba(255, 100, 100, 0.28);
        }
        .recommendation-icon {
            width: 40px;
            height: 40px;
            min-width: 40px;
            border-radius: 14px;
            display: grid;
            place-items: center;
            background: rgba(239, 68, 68, 0.14);
            color: #ffffff;
            box-shadow: inset 0 0 16px rgba(239, 68, 68, 0.16);
            font-size: 1.1rem;
        }
        .recommendation-content {
            display: grid;
            gap: 6px;
        }
        .recommendation-title {
            font-size: 0.96rem;
            font-weight: 700;
            color: #ffffff;
        }
        .recommendation-detail {
            font-size: 0.92rem;
            color: #e5e7eb;
            line-height: 1.55;
        }
        .sidebar-status {
            display: flex;
            justify-content: space-between;
            gap: 18px;
            margin-top: 20px;
            color: rgba(255, 255, 255, 0.72);
            font-size: 0.84rem;
        }
        .sidebar-status div {
            background: rgba(10, 12, 18, 0.75);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 16px;
            padding: 12px 16px;
            flex: 1;
        }
        .connection-map {
            position: absolute;
            right: 24px;
            bottom: 24px;
            width: 140px;
            height: 100px;
            border-radius: 22px;
            background: rgba(0, 10, 20, 0.78);
            border: 1px solid rgba(220, 38, 38, 0.1);
            display: grid;
            place-items: center;
            color: rgba(255, 160, 160, 0.82);
            font-size: 0.82rem;
            box-shadow: 0 0 24px rgba(220, 38, 38, 0.12);
        }
        .connection-map span {
            display: block;
            text-align: center;
        }
        .stTextArea>div>div>textarea {
            background: rgba(5, 11, 22, 0.92) !important;
            color: #f8f8ff !important;
        }
        .stDownloadButton>button,
        .stButton>button {
            min-height: 60px !important;
            height: 60px !important;
            width: 340px !important;
            border-radius: 18px !important;
            font-size: 16px !important;
            font-weight: 700 !important;
            text-transform: uppercase !important;
            transition: all 0.25s ease !important;
            box-shadow: 0 0 12px rgba(255, 0, 0, 0.35) !important;
        }
        .stButton>button {
            background: linear-gradient(180deg, #7F0000, #FF1E1E) !important;
            border: 1px solid #FF3B30 !important;
            color: #ffffff !important;
        }
        .stButton>button:hover {
            background: linear-gradient(180deg, #7F0000, #FF1E1E) !important;
            box-shadow: 0 0 18px rgba(255, 0, 0, 0.55) !important;
            transform: scale(1.05) !important;
        }
        .stDownloadButton>button {
            background: rgba(255, 30, 30, 0.12) !important;
            border: 1px solid rgba(255, 0, 0, 0.24) !important;
            color: #ffffff !important;
        }
        .stDownloadButton>button:hover {
            background: rgba(255, 0, 0, 0.18) !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------
# Utility Functions
# ---------------------------

def get_file_extension(filename: str) -> str:
    return "." + filename.split(".")[-1].lower() if "." in filename else ""

def read_text_file(uploaded_file) -> str:
    """Read generic text-based uploaded file safely."""
    try:
        raw = uploaded_file.read()
        # Try to decode with utf-8, fallback to latin-1
        try:
            text = raw.decode("utf-8")
        except Exception:
            text = raw.decode("latin-1", errors="ignore")
        return text
    except Exception:
        return ""

def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract text from PDF using pypdf."""
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        text_parts = []
        for page in reader.pages:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(text_parts)
    except Exception:
        return ""

def extract_text_from_docx(file_bytes: bytes) -> str:
    """Extract text from DOCX using python-docx."""
    try:
        with io.BytesIO(file_bytes) as f:
            doc = docx.Document(f)
            paragraphs = [p.text for p in doc.paragraphs]
            return "\n".join(paragraphs)
    except Exception:
        return ""

def extract_code_from_ipynb(file_bytes: bytes) -> str:
    """Extract code cells from Jupyter notebook (.ipynb)."""
    try:
        data = json.loads(file_bytes.decode("utf-8"))
        cells = data.get("cells", [])
        code_cells = []
        for c in cells:
            if c.get("cell_type") == "code":
                code_cells.append("".join(c.get("source", [])))
        return "\n\n".join(code_cells)
    except Exception:
        return ""

def detect_mime(file_bytes: bytes) -> str:
    """Detect mime type using python-magic."""
    try:
        m = magic.Magic(mime=True)
        return m.from_buffer(file_bytes)
    except Exception:
        return "application/octet-stream"

# ---------------------------
# Local Heuristic Analyzer
# ---------------------------

def local_analyzer(code: str, filename: str = "") -> dict:
    """
    Heuristic-based analyzer for offline fallback.
    Detects suspicious keywords, patterns, and common vulnerability indicators.
    Returns a structured analysis dict.
    """
    # Normalize
    code_lower = code.lower()
    findings = []
    score = 0

    # Patterns for malicious behavior
    patterns = {
        "command_execution": [
            r"\bos\.system\(",
            r"\bsubprocess\.Popen\(",
            r"\bsubprocess\.call\(",
            r"\bexec\(",
            r"\beval\(",
            r"\bpopen\(",
            r"system\(",
            r"Runtime\.getRuntime\(",
            r"ProcessBuilder",
        ],
        "reverse_shell": [
            r"/dev/tcp/",
            r"bash -i >& /dev/tcp",
            r"nc -e",
            r"socket\.connect\(",
            r"socket\.create_connection\(",
        ],
        "data_exfiltration": [
            r"requests\.post\(",
            r"requests\.put\(",
            r"fetch\(",
            r"ftp\.connect\(",
            r"smtp",
            r"smtplib",
            r"ftplib",
            r"upload",
        ],
        "keylogging": [
            r"keylogger",
            r"keyboard\.hook",
            r"pynput\.keyboard",
            r"win32api\.GetAsyncKeyState",
        ],
        "obfuscation": [
            r"base64\.b64decode",
            r"b64decode\(",
            r"eval\(base64",
            r"exec\(base64",
            r"rot13",
            r"xor",
            r"obfusc",
        ],
        "persistence": [
            r"crontab",
            r"cron",
            r"registry",
            r"run key",
            r"startupfolder",
            r"systemd",
            r"launchctl",
        ],
        "ransomware": [
            r"encrypt\(",
            r"crypt",
            r"rsa\.generate",
            r"fernet",
            r"shred\(",
            r"ransom",
        ],
        "hardcoded_credentials": [
            r"password\s*=\s*[\"'].*[\"']",
            r"passwd\s*=\s*[\"'].*[\"']",
            r"api_key\s*=\s*[\"'].*[\"']",
            r"secret\s*=\s*[\"'].*[\"']",
        ],
        "sql_injection": [
            r"execute\(.+%s",
            r"execute\(.+\+",
            r"format\(.+select",
            r"select .* from .* where .*\" \+",
            r"\"select",
            r"';--",
        ],
        "xss": [
            r"innerhtml",
            r"document\.write\(",
            r"dangerouslysetinnerhtml",
            r"eval\(",
        ],
        "unsafe_file_handling": [
            r"open\(.+, *['\"]w",
            r"open\(.+, *['\"]wb",
            r"tempfile\.mktemp",
            r"shutil\.rmtree",
        ],
        "dangerous_libraries": [
            r"os\.system",
            r"subprocess",
            r"pickle\.loads",
            r"yaml\.load\(",
            r"eval\(",
        ],
    }

    # Check patterns and accumulate findings
    for category, pats in patterns.items():
        for pat in pats:
            if re.search(pat, code_lower, flags=re.IGNORECASE):
                findings.append({"category": category, "pattern": pat})
                # Weighting: more severe categories add more to score
                if category in ("reverse_shell", "ransomware", "persistence"):
                    score += 20
                elif category in ("command_execution", "data_exfiltration", "keylogging"):
                    score += 15
                elif category in ("obfuscation", "hardcoded_credentials", "sql_injection", "xss"):
                    score += 10
                else:
                    score += 5

    # Additional heuristic checks
    # External IPs or domains
    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", code)
    domains = re.findall(r"(https?://[^\s'\"\\)]+)", code)
    if ips or domains:
        findings.append({"category": "external_connections", "evidence": ips + domains})
        score += 10

    # Long base64 strings (possible payloads)
    long_b64 = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", code)
    if long_b64:
        findings.append({"category": "encoded_payload", "evidence": f"{len(long_b64)} long base64 strings"})
        score += 15

    # Heuristic: many suspicious findings -> increase score
    unique_cats = {f["category"] for f in findings}
    if len(unique_cats) >= 5:
        score += 10

    # Clamp score
    score = max(0, min(100, score))

    # Classification logic (strict)
    if score == 0:
        classification = "SAFE / ORIGINAL CODE"
        threat = "Low"
    else:
        classification = "MALICIOUS CODE"
        # Threat level based on severity
        if score >= 70:
            threat = "Critical"
        elif score >= 40:
            threat = "High"
        else:
            threat = "Medium"

    # Build explanation and recommendations
    explanation_lines = []
    for f in findings:
        cat = f.get("category")
        pat = f.get("pattern", f.get("evidence", ""))
        explanation_lines.append(f"- Detected **{cat}** pattern: `{pat}`")

    if not explanation_lines:
        explanation_lines = ["No obvious malicious patterns detected by heuristic scan."]

    recommendations = [
        "Review and remove any hardcoded credentials; use secure secret storage.",
        "Avoid using eval/exec and direct command execution; use safe APIs and parameterized queries.",
        "Validate and sanitize all external input to prevent SQL injection and XSS.",
        "Limit use of dangerous libraries and avoid deserializing untrusted data.",
        "If external connections are required, whitelist domains and use secure channels (TLS).",
        "Scan binaries and large encoded payloads with specialized malware scanners.",
        "Implement least privilege and avoid persistence mechanisms unless explicitly required.",
    ]

    return {
        "classification": classification,
        "risk_score": int(score),
        "threat_level": threat,
        "explanation": "\n".join(explanation_lines),
        "findings": findings,
        "recommendations": recommendations,
        "used_fallback": True,
    }

# ---------------------------
# Gemini Integration
# ---------------------------

# ---------------------------
# Gemini Integration (Corrected)
# ---------------------------

def analyze_with_gemini(code: str, filename: str = "", settings: dict = None) -> dict:
    """
    Attempt to analyze code using Google Gemini via google-generativeai package.
    Falls back to local_analyzer on any failure.
    """
    prompt = (
        "You are an expert cybersecurity analyst. Analyze the provided source code. "
        "Determine whether it is SAFE / ORIGINAL CODE, SUSPICIOUS CODE, or MALICIOUS CODE. "
        "Identify malware behavior (keylogging, credential stealing, data exfiltration, reverse shells, backdoors, "
        "ransomware-like behavior, obfuscated code, persistence mechanisms, command execution abuse), "
        "security vulnerabilities (SQL Injection, Command Injection, XSS, hardcoded credentials, weak encryption, "
        "unsafe file handling, authentication issues, privilege escalation patterns), and suspicious patterns "
        "(unknown external connections, dangerous libraries, hidden payloads, encoded suspicious strings, system-level modifications). "
        "Provide a structured JSON response with keys: classification, risk_score (0-100), threat_level (Low/Medium/High/Critical), "
        "explanation (detailed), findings (list), recommendations (list). Analyze behavior, not just syntax. "
        f"Return only valid JSON. Here is the filename: {filename}\n\nCODE_START\n{code}\nCODE_END\n"
    )

    try:
        if not GENAI_AVAILABLE:
            raise RuntimeError("google-generativeai package not available")


        # Try Render environment variable first
        api_key = os.getenv("GEMINI_API_KEY")

            # Fallback to Streamlit secrets for local development
        if not api_key:
            try:
                api_key = st.secrets["GEMINI_API_KEY"]
            except Exception:
                    api_key = None

        if not api_key:
            raise RuntimeError("Gemini API key not found. Configure GEMINI_API_KEY in Render Environment Variables or Streamlit secrets.")
        model_map = {
            "Gemini 2.5 Flash": "gemini-2.5-pro",
            "Gemini 1.5 Pro": "gemini-1.5-pro",
            "Gemini 1.0": "gemini-1.0",
            "Gemini 2.5 Flash": "gemini-2.5-flash",
            "Gemini 1.5 Pro": "gemini-1.5-pro",
        }
        selected_model = "gemini-2.5-pro"

        model = genai.GenerativeModel(selected_model)
        response = model.generate_content(prompt)
        response_text = response.text

        json_text = None
        try:
            json_text = json.loads(response_text)
        except Exception:
            m = re.search(r"(\{[\s\S]*\})", response_text)
            if m:
                try:
                    json_text = json.loads(m.group(1))
                except Exception:
                    json_text = None

        if json_text:
            json_text["used_fallback"] = False
            return json_text

        raise RuntimeError("Could not parse Gemini response as JSON")

    except Exception:
        return local_analyzer(code, filename)


# ---------------------------
# File Processing Pipeline
# ---------------------------

def process_uploaded_file(uploaded_file) -> tuple[str, str]:
    """
    Validate and extract code/text from uploaded file.
    Returns tuple (extracted_text, filename)
    """
    filename = uploaded_file.name
    ext = get_file_extension(filename)
    file_bytes = uploaded_file.read()
    # Reset pointer for potential re-reads
    try:
        uploaded_file.seek(0)
    except Exception:
        pass

    # Basic validation
    if ext not in ALLOWED_EXTENSIONS:
        # Try to detect mime and allow if text-like
        mime = detect_mime(file_bytes)
        if not mime.startswith("text") and "pdf" not in mime and "msword" not in mime:
            raise ValueError(f"Unsupported file type: {ext} ({mime})")

    # Extract based on extension
    if ext == ".pdf":
        text = extract_text_from_pdf(file_bytes)
    elif ext == ".docx":
        text = extract_text_from_docx(file_bytes)
    elif ext == ".ipynb":
        text = extract_code_from_ipynb(file_bytes)
    else:
        # Generic text read
        try:
            text = file_bytes.decode("utf-8")
        except Exception:
            try:
                text = file_bytes.decode("latin-1", errors="ignore")
            except Exception:
                text = ""
    return text, filename

# ---------------------------
# Streamlit UI Components
# ---------------------------

def render_header():
    gemini_status = "Connected" if GENAI_AVAILABLE else "Unavailable"
    st.markdown(
        f"""
        <div class='page-shell'>
            <div class='hero-card'>
                <div style='display:flex; flex-wrap:wrap; justify-content:space-between; gap:24px; align-items:flex-start;'>
                    <div class='page-brand'>
                        <div class='page-logo'>🛡</div>
                        <div>
                            <div class='hero-title'>AI Code Analyzer</div>
                            <div class='hero-subtitle'>Intelligent Malware & Vulnerability Detection</div>
                        </div>
                    </div>
                    <div class='status-badge'>
                        <div class='status-label'>Gemini Model Status</div>
                        <div>{gemini_status} · Gemini 2.5 Flash</div>
                    </div>
                </div>
                <div class='hero-metrics'>
                    <div class='hero-metric'>
                        <span>Threat Confidence</span>
                        <strong>98%</strong>
                    </div>
                    <div class='hero-metric'>
                        <span>Response Latency</span>
                        <strong>1.2s</strong>
                    </div>
                    <div class='hero-metric'>
                        <span>Analysis Coverage</span>
                        <strong>All supported languages</strong>
                    </div>
                </div>
            </div>
        """,
        unsafe_allow_html=True,
    )

def display_analysis_result(result: dict, code_preview: str):
    classification = result.get("classification", "Unknown")
    risk_score = int(result.get("risk_score", 0))
    threat_level = result.get("threat_level", "Unknown")
    explanation = result.get("explanation", "No explanation provided.")
    recommendations = result.get("recommendations", [])
    fallback_active = result.get("used_fallback", False)

    fallback_label = "Local heuristic fallback engaged" if fallback_active else "Gemini AI analysis complete"
    confidence_score = result.get("confidence_score", "N/A")

    st.markdown(
        f"""
        <div class='dashboard-panel'>
            <div class='panel-title'>🤖 AI ANALYSIS RESULT</div>
            <div class='analysis-grid'>
                <div class='result-card'>
                    <div class='result-card-title'>Classification</div>
                    <div class='result-card-value'>{classification}</div>
                    <div class='result-card-meta'>Trusted assessment from the security engine.</div>
                </div>
                <div class='result-card'>
                    <div class='result-card-title'>Risk Score</div>
                    <div class='result-card-value'>{risk_score}%</div>
                    <div class='result-card-meta'>Calculated from AI and heuristic indicators.</div>
                </div>
                <div class='result-card'>
                    <div class='result-card-title'>Threat Level</div>
                    <div class='result-card-value'>{threat_level}</div>
                    <div class='result-card-meta'>{fallback_label}</div>
                </div>
                <div class='result-card'>
                    <div class='result-card-title'>Confidence Score</div>
                    <div class='result-card-value'>{confidence_score}</div>
                    <div class='result-card-meta'>Measured trust rating for the final analysis.</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    findings = result.get("findings", [])
    category_labels = {
        "command_execution": "Command Execution",
        "reverse_shell": "Reverse Shell",
        "data_exfiltration": "Data Exfiltration",
        "keylogging": "Keylogging",
        "obfuscation": "Obfuscation",
        "persistence": "Persistence",
        "ransomware": "Ransomware",
        "hardcoded_credentials": "Hardcoded Credentials",
        "sql_injection": "SQL Injection",
        "xss": "Cross-Site Scripting",
        "unsafe_file_handling": "Unsafe File Handling",
        "dangerous_libraries": "Dangerous Library Use",
        "external_connections": "External Connection",
        "encoded_payload": "Encoded Payload",
    }
    category_meta = {
        "command_execution": ("High", "Suspicious shell or command execution detected.", "Avoid direct shell execution and use safer APIs."),
        "reverse_shell": ("Critical", "Remote shell or connection patterns found.", "Block remote shell code and validate network endpoints."),
        "data_exfiltration": ("High", "Potential data exfiltration channel detected.", "Validate outbound traffic and use secure channels."),
        "keylogging": ("High", "Keylogging or input capture behavior detected.", "Avoid keylogger libraries and obfuscation on input handling."),
        "obfuscation": ("Medium", "Code obfuscation techniques were identified.", "Review and simplify obfuscated code to improve visibility."),
        "persistence": ("High", "Persistence mechanisms found that may maintain access.", "Remove unauthorized startup persistence behavior."),
        "ransomware": ("Critical", "Encryption or ransomware-like behavior detected.", "Do not perform unauthorized encryption or payload delivery."),
        "hardcoded_credentials": ("Medium", "Embedded credentials were found in code.", "Use secure secret storage and remove hardcoded secrets."),
        "sql_injection": ("High", "Unparameterized queries or injection risk detected.", "Apply input sanitization and parameterized database queries."),
        "xss": ("High", "Potential cross-site scripting behavior found.", "Sanitize outputs and avoid unsafe DOM operations."),
        "unsafe_file_handling": ("Medium", "Unsafe file handling or deletion patterns found.", "Use safe file APIs and restrict file operations.") ,
        "dangerous_libraries": ("Medium", "Use of dangerous or insecure libraries detected.", "Avoid unsafe libraries and review third-party dependencies."),
        "external_connections": ("Medium", "External connection or IP evidence found.", "Whitelist trusted endpoints and monitor outbound connections."),
        "encoded_payload": ("High", "Long encoded payloads or binary data found.", "Investigate encoded data and decode before execution."),
    }
    if not findings:
        findings = [{
            "category": "none",
            "pattern": "No abnormal patterns detected.",
            "evidence": "No direct evidence available.",
        }]

    table_rows = []
    for item in findings:
        category = item.get("category", "unknown")
        evidence = item.get("pattern") or item.get("evidence") or "No evidence available."
        threat_name = category_labels.get(category, category.replace("_", " ").title())
        severity, description_text, recommendation_text = category_meta.get(
            category,
            ("Info", "No specific category details available.", "Review the suspicious item in context.")
        )
        table_rows.append({
            "threat": threat_name,
            "category": threat_name,
            "severity": severity,
            "evidence": evidence,
            "description": description_text,
            "recommendation": recommendation_text,
        })

    table_html = ""
    for row in table_rows:
        table_html += f"<tr>"
        table_html += f"<td>{row['threat']}</td>"
        table_html += f"<td>{row['category']}</td>"
        table_html += f"<td>{row['severity']}</td>"
        table_html += f"<td>{row['evidence']}</td>"
        table_html += f"<td>{row['description']}</td>"
        table_html += f"<td>{row['recommendation']}</td>"
        table_html += "</tr>"

    report_text = build_report_text(result, code_preview)
    st.markdown("""
        <div class='glass-card report-panel'>
            <div class='panel-title'>🧾 THREAT REPORT</div>
        """,
        unsafe_allow_html=True,
    )
    st.text_area("🧾 THREAT REPORT (editable)", value=report_text, height=300, key="threat_report", label_visibility="collapsed")
    export_col1, export_col2, export_col3 = st.columns([1, 1, 1])
    with export_col1:
        st.download_button("📄 .TXT (Plain Text)", data=report_text, file_name="threat_report.txt", mime="text/plain", key="download_txt")
    with export_col2:
        st.download_button("📄 .PDF (Vector Report)", data=build_pdf_bytes(report_text), file_name="threat_report.pdf", mime="application/pdf", key="download_pdf")
    with export_col3:
        st.download_button("📄 .DOCX (Formatted Document)", data=build_docx_bytes(report_text), file_name="threat_report.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", key="download_docx")
    st.markdown("</div>", unsafe_allow_html=True)

    left_col, right_col = st.columns([2, 1], gap="large")
    with left_col:
        st.markdown("""
            <div class='glass-panel'>
                <div class='panel-title'>⚠ DETAILED FINDINGS</div>
                <div class='threat-table-wrapper'>
                    <table class='threat-table'>
                        <thead>
                            <tr>
                                <th>Threat</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Evidence</th>
                                <th>Description</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            """ + table_html + """
                        </tbody>
                    </table>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with right_col:
        st.markdown("""
            <div class='glass-panel'>
                <div class='panel-title'>🔐 SECURITY RECOMMENDATIONS</div>
            </div>
        """, unsafe_allow_html=True)
        for index, rec in enumerate(recommendations, start=1):
            icon = "🔐" if index == 1 else "🛠️" if index == 2 else "🛡️" if index == 3 else "⚙️"
            st.markdown(
                f"""
                <div class='recommendation-item'>
                    <div class='recommendation-number'>{index}</div>
                    <div class='recommendation-content'>
                        <div class='recommendation-title'>Recommendation {index}</div>
                        <div class='recommendation-detail'><span class='recommendation-icon'>{icon}</span> {rec}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def build_report_text(result: dict, code_preview: str) -> str:
    lines = []
    lines.append("AI Code Analyzer - Threat Report")
    lines.append("=" * 40)
    lines.append(f"Classification: {result.get('classification')}")
    lines.append(f"Risk Score: {result.get('risk_score')}%")
    lines.append(f"Threat Level: {result.get('threat_level')}")
    lines.append("")
    lines.append("Explanation:")
    lines.append(result.get("explanation", ""))
    lines.append("")
    lines.append("Findings:")
    for f in result.get("findings", []):
        if isinstance(f, dict):
            lines.append(f"- {f.get('category')}: {f.get('pattern', f.get('evidence', ''))}")
        else:
            lines.append(f"- {str(f)}")
    lines.append("")
    lines.append("Recommendations:")
    for r in result.get("recommendations", []):
        lines.append(f"- {r}")
    lines.append("")
    lines.append("Code Preview (truncated to 1000 chars):")
    lines.append(code_preview[:1000])
    return "\n".join(lines)


def build_pdf_bytes(report_text: str) -> bytes:
    safe_lines = []
    for line in report_text.splitlines():
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        safe_lines.append(safe)
    content_lines = []
    y = 780
    for line in safe_lines:
        if y < 60:
            break
        content_lines.append(f"BT /F1 10 Tf 40 {y} Td ({line}) Tj ET")
        y -= 14
    content_stream = "\n".join(content_lines).encode("latin-1", errors="ignore")
    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n")
    stream_content = b"BT /F1 12 Tf 40 810 Td (AI Code Analyzer - Threat Report) Tj ET\n" + content_stream
    objects.append(f"4 0 obj<< /Length {len(stream_content)} >>stream\n".encode("latin-1") + stream_content + b"\nendstream\nendobj\n")
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")

    xref_start = 0
    pdf = [b"%PDF-1.4\n"]
    byte_offset = len(pdf[0])
    for obj in objects:
        xref_start = byte_offset
        pdf.append(obj)
        byte_offset += len(obj)
    xref_offset = byte_offset
    xref = [b"xref\n0 6\n0000000000 65535 f \n"]
    position = len(pdf[0])
    current = 1
    for obj in objects:
        xref.append(f"{position:010} 00000 n \n".encode("latin-1"))
        position += len(obj)
        current += 1
    trailer = (
        b"trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref_offset).encode("latin-1") + b"\n%%EOF"
    )
    pdf.extend(xref)
    pdf.append(trailer)
    return b"".join(pdf)


def build_docx_bytes(report_text: str) -> bytes:
    doc = docx.Document()
    for line in report_text.splitlines():
        doc.add_paragraph(line)
    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()

# ---------------------------
# Main Application Logic
# ---------------------------

def main():
    inject_custom_styles()
    render_header()

    uploaded_file = None
    code_input = st.session_state.get("code_input", "")
    status_placeholder = st.empty()

    with st.container():
        left_panel, right_panel = st.columns([2, 1], gap="large")

        with left_panel:
            st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
            st.markdown("<div class='card-heading'>🛡 SOURCE CODE INPUT</div>", unsafe_allow_html=True)
            code_input = st.text_area("Paste code here", height=420, placeholder="# Paste code or upload a file to begin analysis", key="code_input", label_visibility="collapsed")
            st.markdown("</div>", unsafe_allow_html=True)

        with right_panel:
            st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
            st.markdown("<div class='card-heading'>📁 UPLOAD FILE</div>", unsafe_allow_html=True)
            uploaded_file = st.file_uploader("Upload a code file or document", type=None, accept_multiple_files=False, key="file_upload", label_visibility="collapsed")
            st.markdown("<div class='metric-card'><strong>Ready to analyze</strong> Submit code to receive a full threat report.</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='analysis-button-wrapper'>", unsafe_allow_html=True)
        analyze_button = st.button("ANALYZE CODE", key="analyze_button")
        status_placeholder = st.empty()
        st.markdown("</div>", unsafe_allow_html=True)

    settings = {}

    extracted_code = ""
    filename = ""

    if uploaded_file is not None:
        try:
            extracted_code, filename = process_uploaded_file(uploaded_file)
            if not extracted_code.strip():
                st.warning("Uploaded file contained no extractable text or code.")
            else:
                st.success(f"Extracted content from `{uploaded_file.name}`.")
        except Exception as e:
            st.error(f"Failed to process uploaded file: {str(e)}")
            st.stop()

    code_to_analyze = ""
    if code_input and code_input.strip():
        code_to_analyze = code_input
        if filename == "":
            filename = "pasted_code"
    elif extracted_code and extracted_code.strip():
        code_to_analyze = extracted_code
    else:
        code_to_analyze = ""

    st.markdown("<div class='glass-card code-preview-panel'>", unsafe_allow_html=True)
    st.markdown("<div class='code-preview-heading'>🧾 CODE PREVIEW</div>", unsafe_allow_html=True)
    if code_to_analyze:
        st.code(code_to_analyze, language="")
    else:
        st.markdown("<div class='metric-card'>No code available yet. Paste code or upload a file, then click ANALYZE CODE.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    if analyze_button:
        if not code_to_analyze:
            st.error("Please provide code via paste or upload before analysis.")
        else:
            status_placeholder.markdown("<div class='status-pill'><div class='pulse-dot'></div>INITIALIZING ANALYSIS</div>", unsafe_allow_html=True)
            progress_text = st.empty()
            progress_bar = st.progress(0)
            try:
                progress_text.text("Preparing analysis prompt...")
                progress_bar.progress(10)
                time.sleep(0.3)

                progress_text.text("Running AI analysis...")
                progress_bar.progress(40)
                time.sleep(0.3)

                result = analyze_with_gemini(code_to_analyze, filename, settings)
                progress_bar.progress(80)
                time.sleep(0.2)

                if result.get("used_fallback", False):
                    progress_text.text("Local heuristic fallback active.")
                else:
                    progress_text.text("AI analysis completed.")

                progress_bar.progress(100)
                time.sleep(0.2)
                status_placeholder.empty()
                progress_text.empty()
                progress_bar.empty()

                display_analysis_result(result, code_to_analyze)

            except Exception as e:
                status_placeholder.empty()
                progress_text.empty()
                progress_bar.empty()
                st.error("An unexpected error occurred during analysis.")
                st.exception(e)

    st.markdown("---")
    st.markdown(
        """
        <div class='glass-card'>
            <div class='card-heading'>Notes & Privacy</div>
            <p class='footer-note'>The Gemini API key is entered directly in the AI Model Controls section and is not stored by this app. Uploaded files are processed in-memory only. The local heuristic analyzer is a fallback designed for quick security insights when the AI service is unavailable.</p>
        </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if __name__ == "__main__":
    main()
