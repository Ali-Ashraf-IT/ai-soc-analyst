import streamlit as st
import json
import pandas as pd
import datetime

from modules.log_parser import LogParser
from modules.ioc_extractor import IOCExtractor
from modules.llm_client import LLMClient
from modules.investigator import Investigator
from modules.mitre_mapper import MitreMapper
from modules.risk_engine import RiskEngine
from modules.response_engine import ResponseEngine

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI SOC Analyst — Incident Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS — Dark SIEM Dashboard Theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ───────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #070d1a;
    color: #cdd6f4;
}
.stApp { background-color: #070d1a; }

/* ── Sidebar ────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1526 0%, #0a1020 100%);
    border-right: 1px solid #1e2d4a;
}
[data-testid="stSidebar"] * { color: #a6adc8 !important; }
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 { color: #cdd6f4 !important; }
[data-testid="stSidebar"] .stButton>button {
    background: linear-gradient(135deg, #1e3a5f, #0f2d4a);
    color: #74c7ec !important;
    border: 1px solid #1e4a7a;
    border-radius: 6px;
    font-weight: 600;
    width: 100%;
    transition: all 0.2s;
}
[data-testid="stSidebar"] .stButton>button:hover {
    background: linear-gradient(135deg, #2a5080, #1a3d60);
    border-color: #74c7ec;
    transform: translateY(-1px);
}

/* ── Headers ────────────────────────────────────────────────── */
h1, h2, h3 { color: #cdd6f4; }
h1 { border-bottom: 2px solid #1e3a5f; padding-bottom: 8px; }

/* ── Tabs ───────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: #0d1526;
    border-radius: 8px;
    padding: 4px;
    border: 1px solid #1e2d4a;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    color: #6c7086 !important;
    background: transparent;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    font-size: 13px;
}
.stTabs [aria-selected="true"] {
    background: #1e3a5f !important;
    color: #74c7ec !important;
}

/* ── Metric Cards ───────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #0d1526;
    border: 1px solid #1e2d4a;
    border-radius: 10px;
    padding: 16px 20px;
}
[data-testid="stMetricLabel"] { color: #6c7086 !important; font-size: 12px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
[data-testid="stMetricValue"] { color: #cdd6f4 !important; font-size: 28px; font-weight: 700; }

/* ── Tables ─────────────────────────────────────────────────── */
.stDataFrame, [data-testid="stTable"] {
    background: #0d1526 !important;
    border: 1px solid #1e2d4a;
    border-radius: 8px;
}

/* ── Expanders ──────────────────────────────────────────────── */
[data-testid="stExpander"] {
    background: #0d1526;
    border: 1px solid #1e2d4a !important;
    border-radius: 8px;
    margin-bottom: 8px;
}
[data-testid="stExpander"] summary { color: #cdd6f4 !important; font-weight: 600; }

/* ── Code Blocks ────────────────────────────────────────────── */
.stCodeBlock { background: #11182b !important; border: 1px solid #1e2d4a; border-radius: 6px; }
code { font-family: 'JetBrains Mono', monospace; color: #a6e3a1; font-size: 12px; }

/* ── Text inputs ────────────────────────────────────────────── */
.stTextInput>div>div>input,
.stTextArea>div>div>textarea,
.stSelectbox>div>div {
    background: #0d1526 !important;
    border: 1px solid #1e2d4a !important;
    color: #cdd6f4 !important;
    border-radius: 6px;
}

/* ── Alerts ─────────────────────────────────────────────────── */
.stAlert { border-radius: 8px; border-left-width: 4px; }

/* ── Progress bar ───────────────────────────────────────────── */
.stProgress > div > div { background-color: #74c7ec !important; border-radius: 4px; }

/* ── Custom Components ──────────────────────────────────────── */
.soc-header {
    background: linear-gradient(135deg, #0d1526 0%, #0a1937 50%, #0d1526 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 20px 28px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.soc-header-title { font-size: 22px; font-weight: 700; color: #74c7ec; }
.soc-header-sub { font-size: 13px; color: #6c7086; margin-top: 2px; }

.severity-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.severity-critical { background: rgba(243,76,80,0.15); color: #f38ba8; border: 1px solid rgba(243,76,80,0.4); }
.severity-high     { background: rgba(250,179,135,0.15); color: #fab387; border: 1px solid rgba(250,179,135,0.4); }
.severity-medium   { background: rgba(249,226,175,0.15); color: #f9e2af; border: 1px solid rgba(249,226,175,0.4); }
.severity-low      { background: rgba(166,227,161,0.15); color: #a6e3a1; border: 1px solid rgba(166,227,161,0.4); }
.severity-fp       { background: rgba(116,199,236,0.15); color: #74c7ec; border: 1px solid rgba(116,199,236,0.4); }

.stat-card {
    background: #0d1526;
    border: 1px solid #1e2d4a;
    border-radius: 10px;
    padding: 18px 20px;
    text-align: center;
    transition: border-color 0.2s;
}
.stat-card:hover { border-color: #74c7ec; }
.stat-card-value { font-size: 32px; font-weight: 700; color: #74c7ec; line-height: 1; }
.stat-card-label { font-size: 11px; color: #6c7086; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 6px; }

.timeline-item {
    display: flex;
    gap: 14px;
    padding: 10px 0;
    border-bottom: 1px solid #1e2d4a;
    align-items: flex-start;
}
.timeline-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    margin-top: 5px;
    flex-shrink: 0;
}
.timeline-dot-critical { background: #f38ba8; box-shadow: 0 0 6px #f38ba8; }
.timeline-dot-high     { background: #fab387; box-shadow: 0 0 6px #fab387; }
.timeline-dot-medium   { background: #f9e2af; box-shadow: 0 0 6px #f9e2af; }
.timeline-dot-low      { background: #a6e3a1; box-shadow: 0 0 6px #a6e3a1; }
.timeline-text { font-size: 13px; color: #cdd6f4; font-family: 'JetBrains Mono', monospace; }

.ioc-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    margin-right: 4px;
}
.ioc-ip      { background: rgba(243,76,80,0.15); color: #f38ba8; }
.ioc-hash    { background: rgba(203,166,247,0.15); color: #cba6f7; }
.ioc-domain  { background: rgba(137,220,235,0.15); color: #89dceb; }
.ioc-user    { background: rgba(249,226,175,0.15); color: #f9e2af; }
.ioc-process { background: rgba(166,227,161,0.15); color: #a6e3a1; }

.mitre-card {
    background: #0d1526;
    border: 1px solid #1e2d4a;
    border-left: 3px solid #74c7ec;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.mitre-id { font-family: 'JetBrains Mono', monospace; color: #74c7ec; font-weight: 700; font-size: 14px; }
.mitre-name { color: #cdd6f4; font-weight: 600; margin-left: 10px; }
.mitre-evidence { color: #6c7086; font-size: 12px; margin-top: 6px; }

.playbook-action {
    background: #0d1526;
    border: 1px solid #1e2d4a;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 12px;
}
.playbook-action-title { color: #cdd6f4; font-weight: 600; font-size: 14px; }
.approval-badge {
    display: inline-block;
    background: rgba(243,76,80,0.15);
    color: #f38ba8;
    border: 1px solid rgba(243,76,80,0.4);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.readonly-badge {
    display: inline-block;
    background: rgba(166,227,161,0.15);
    color: #a6e3a1;
    border: 1px solid rgba(166,227,161,0.4);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
}

.decision-box {
    border-radius: 10px;
    padding: 16px 24px;
    font-size: 16px;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0.05em;
    margin: 12px 0;
}
.decision-tp        { background: rgba(243,76,80,0.12); border: 2px solid #f38ba8; color: #f38ba8; }
.decision-incident  { background: rgba(250,179,135,0.12); border: 2px solid #fab387; color: #fab387; }
.decision-fp        { background: rgba(166,227,161,0.12); border: 2px solid #a6e3a1; color: #a6e3a1; }
.decision-suspicious{ background: rgba(249,226,175,0.12); border: 2px solid #f9e2af; color: #f9e2af; }
.decision-benign    { background: rgba(116,199,236,0.12); border: 2px solid #74c7ec; color: #74c7ec; }

.progress-step {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 0;
    font-size: 13px;
    color: #6c7086;
}
.progress-step.done { color: #a6e3a1; }
.progress-step.active { color: #74c7ec; }
.step-icon { font-size: 16px; }

.divider { border: none; border-top: 1px solid #1e2d4a; margin: 16px 0; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "investigation": None,
        "iocs": None,
        "events": None,
        "mitre": None,
        "risk": None,
        "response": None,
        "raw_logs": None,
        "pipeline_done": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def severity_badge(sev: str) -> str:
    cls_map = {
        "critical": "severity-critical",
        "high":     "severity-high",
        "medium":   "severity-medium",
        "low":      "severity-low",
        "false positive": "severity-fp",
    }
    cls = cls_map.get(str(sev).lower(), "severity-low")
    return f'<span class="severity-badge {cls}">{sev}</span>'


def decision_box(decision: str) -> str:
    d = str(decision).lower()
    if "false positive" in d:
        cls = "decision-fp"
    elif "incident confirmed" in d:
        cls = "decision-incident"
    elif "true positive" in d:
        cls = "decision-tp"
    elif "suspicious" in d:
        cls = "decision-suspicious"
    else:
        cls = "decision-benign"
    return f'<div class="decision-box {cls}">🔍 {decision}</div>'


def timeline_dot_color(idx: int, total: int) -> str:
    pct = idx / max(total - 1, 1)
    if pct > 0.75:
        return "timeline-dot-critical"
    elif pct > 0.5:
        return "timeline-dot-high"
    elif pct > 0.25:
        return "timeline-dot-medium"
    return "timeline-dot-low"


def ioc_badge(ioc_type: str) -> str:
    cls_map = {
        "ipv4": "ioc-ip", "ip": "ioc-ip",
        "sha256": "ioc-hash", "md5": "ioc-hash", "sha1": "ioc-hash",
        "domain": "ioc-domain",
        "users": "ioc-user",
        "processes": "ioc-process",
        "email": "ioc-domain",
    }
    cls = cls_map.get(ioc_type.lower(), "ioc-domain")
    label = ioc_type.upper().replace("IPV4", "IP")
    return f'<span class="ioc-badge {cls}">{label}</span>'


def build_markdown_report() -> str:
    inv  = st.session_state.investigation or {}
    risk = st.session_state.risk or {}
    mitre = st.session_state.mitre or []
    resp = st.session_state.response or {}
    iocs = st.session_state.iocs or {}
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# 🛡️ SOC Investigation Report",
        f"**Generated:** {ts}",
        f"",
        f"## 🎯 Alert Severity & Classification",
        f"- **Severity:** {risk.get('severity','N/A')}",
        f"- **Risk Score:** {risk.get('score','N/A')}/100",
        f"- **Classification:** {inv.get('classification','N/A')}",
        f"- **Confidence:** {int(float(inv.get('confidence',0))*100)}%",
        f"- **Decision:** {inv.get('decision','N/A')}",
        f"",
        f"## 🔍 Executive Summary",
        inv.get("summary", "N/A"),
        f"",
        f"## 🔎 Investigation Findings",
    ]
    for f in inv.get("findings", []):
        lines.append(f"- {f}")

    lines += ["", "## 🧭 Attack Timeline"]
    for t in inv.get("timeline", []):
        lines.append(f"- {t}")

    lines += ["", "## 🧩 Indicators of Compromise"]
    lines.append("| Type | Indicator |")
    lines.append("|------|-----------|")
    for ioc_type, values in iocs.items():
        for v in values:
            lines.append(f"| {ioc_type.upper()} | `{v}` |")

    lines += ["", "## 🧠 Root Cause Analysis"]
    rc = inv.get("root_cause", {})
    lines.append(f"**Cause:** {rc.get('cause','N/A')}")
    lines.append(f"**Evidence:** {rc.get('evidence','N/A')}")
    lines.append(f"**Confidence:** {rc.get('confidence','N/A')}")

    lines += ["", "## 📌 MITRE ATT&CK Mapping"]
    lines.append("| ID | Technique | Evidence | Confidence |")
    lines.append("|----|-----------|----------|------------|")
    for m in mitre:
        lines.append(f"| {m.get('technique_id','N/A')} | {m.get('technique_name','N/A')} | {m.get('evidence','N/A')} | {m.get('confidence','N/A')} |")

    for phase in ["containment", "eradication", "recovery", "remediation"]:
        lines += ["", f"## 🛡️ {phase.capitalize()}"]
        for a in resp.get(phase, []):
            lines.append(f"- **{a.get('action','N/A')}** — _{a.get('reason','N/A')}_")
            lines.append(f"  - Command: `{a.get('command_example','N/A')}`")
            lines.append(f"  - Risk: {a.get('risk','N/A')} | Requires Approval: {a.get('requires_approval','YES')}")

    lines += ["", "## ⚠️ Additional Evidence Required"]
    for e in inv.get("additional_evidence_required", []):
        lines.append(f"- {e}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 10px 0 20px 0;'>
        <div style='font-size:36px;'>🛡️</div>
        <div style='font-size:16px; font-weight:700; color:#74c7ec;'>AI SOC Analyst</div>
        <div style='font-size:11px; color:#6c7086; margin-top:2px;'>Incident Response Platform</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### ⚙️ LLM Configuration")
    api_key  = st.text_input("API Key", type="password", placeholder="gsk_... or sk-...")
    base_url = st.text_input("Base URL", value="https://api.groq.com/openai/v1")
    model    = st.text_input("Model", value="llama-3.1-70b-versatile",
                             help="Groq: llama-3.1-70b-versatile | OpenRouter: openai/gpt-4o-mini")

    st.markdown("---")
    st.markdown("#### 📁 Log Ingestion")
    uploaded_files = st.file_uploader(
        "Upload Log Files",
        accept_multiple_files=True,
        type=["txt", "log", "csv", "json"],
        help="Supports .txt .log .csv .json"
    )
    raw_logs_text = st.text_area(
        "Or Paste Raw Logs",
        height=160,
        placeholder="Paste any log format here…"
    )

    st.markdown("---")
    col_a, col_b = st.columns(2)
    start_btn = col_a.button("🔍 Investigate", type="primary", use_container_width=True)
    clear_btn = col_b.button("🗑️ Clear", use_container_width=True)

    if clear_btn:
        st.session_state.clear()
        init_state()
        st.rerun()

    st.markdown("---")
    st.markdown("""
    <div style='font-size:11px; color:#45475a; line-height:1.6;'>
    <b style='color:#6c7086;'>Supported Log Types</b><br>
    Windows Event Logs · Sysmon<br>
    Firewall · VPN · Auth Logs<br>
    EDR · IDS/IPS · DNS · Proxy<br>
    Web Server · Email Security
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
def run_pipeline():
    if not api_key:
        st.error("⚠️ API Key is required. Enter it in the sidebar.")
        return

    raw_text = raw_logs_text or ""
    if uploaded_files:
        for f in uploaded_files:
            try:
                raw_text += "\n" + f.getvalue().decode("utf-8", errors="ignore")
            except Exception as e:
                st.warning(f"Could not read {f.name}: {e}")

    if not raw_text.strip():
        st.error("No logs provided. Upload a file or paste raw logs.")
        return

    st.session_state.raw_logs = raw_text

    # ── Stage-by-stage progress UI ────────────────────────────────────────────
    progress_container = st.empty()
    stages = [
        ("📂", "Parsing logs"),
        ("🔎", "Extracting IOCs"),
        ("🤖", "Running AI investigation"),
        ("🗺️", "Mapping MITRE ATT&CK"),
        ("📊", "Calculating risk score"),
        ("📋", "Generating IR playbook"),
    ]

    def render_progress(done_idx: int):
        html = "<div style='background:#0d1526;border:1px solid #1e2d4a;border-radius:10px;padding:16px 20px;'>"
        html += "<div style='font-size:13px;font-weight:700;color:#74c7ec;margin-bottom:12px;'>🔄 Investigation Pipeline</div>"
        for i, (icon, label) in enumerate(stages):
            if i < done_idx:
                html += f"<div class='progress-step done'><span class='step-icon'>✅</span>{label}</div>"
            elif i == done_idx:
                html += f"<div class='progress-step active'><span class='step-icon'>{icon}</span><b>{label}…</b></div>"
            else:
                html += f"<div class='progress-step'><span class='step-icon'>{icon}</span>{label}</div>"
        html += "</div>"
        progress_container.markdown(html, unsafe_allow_html=True)

    try:
        # Stage 0: Parse
        render_progress(0)
        events = LogParser.parse_logs(raw_text)
        st.session_state.events = events

        # Stage 1: IOC Extraction
        render_progress(1)
        iocs = IOCExtractor.extract(events)
        st.session_state.iocs = iocs

        # Stage 2: Investigate (limit to 80 events to stay within token budget)
        render_progress(2)
        client = LLMClient(api_key=api_key, base_url=base_url, model=model)
        investigator = Investigator(client)
        limited_events = events[:80]
        inv_result = investigator.investigate(limited_events, iocs)

        if "error" in inv_result:
            progress_container.empty()
            st.error(f"AI Investigation Error: {inv_result['error']}")
            return

        st.session_state.investigation = inv_result

        # Stage 3: MITRE
        render_progress(3)
        mitre_mapper = MitreMapper(client)
        st.session_state.mitre = mitre_mapper.map_to_mitre(inv_result, limited_events)

        # Stage 4: Risk
        render_progress(4)
        st.session_state.risk = RiskEngine.calculate_risk(inv_result, iocs)

        # Stage 5: Playbook
        render_progress(5)
        resp_engine = ResponseEngine(client)
        st.session_state.response = resp_engine.generate_playbook(inv_result, iocs)

        render_progress(len(stages))
        st.session_state.pipeline_done = True
        progress_container.empty()
        st.rerun()

    except Exception as e:
        progress_container.empty()
        st.error(f"Pipeline Error: {e}")


if start_btn:
    run_pipeline()


# ─────────────────────────────────────────────────────────────────────────────
# LANDING STATE
# ─────────────────────────────────────────────────────────────────────────────
if not st.session_state.pipeline_done:
    st.markdown("""
    <div class='soc-header'>
        <div>
            <div class='soc-header-title'>🛡️ AI SOC Analyst — Incident Response Platform</div>
            <div class='soc-header-sub'>Paste or upload security logs → Click Investigate → Receive a full SOC investigation report</div>
        </div>
        <div style='font-size:12px; color:#45475a; text-align:right;'>
            Powered by LLM + MITRE ATT&CK<br>
            Evidence-Based · Agentic · Safe
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class='stat-card'>
            <div class='stat-card-value'>🔍</div>
            <div class='stat-card-label'>Agentic Investigation</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class='stat-card'>
            <div class='stat-card-value'>🧠</div>
            <div class='stat-card-label'>MITRE ATT&CK Mapping</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class='stat-card'>
            <div class='stat-card-value'>📋</div>
            <div class='stat-card-label'>IR Playbook Generation</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.info("👈 Configure your API key and paste security logs in the sidebar, then click **Investigate**.")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD — DATA
# ─────────────────────────────────────────────────────────────────────────────
inv   = st.session_state.investigation or {}
risk  = st.session_state.risk or {}
iocs  = st.session_state.iocs or {}
mitre = st.session_state.mitre or []
resp  = st.session_state.response or {}
events = st.session_state.events or []

severity   = risk.get("severity", "Unknown")
risk_score = risk.get("score", 0)
confidence = int(float(inv.get("confidence", 0)) * 100)
decision   = inv.get("decision", "UNKNOWN")
total_iocs = sum(len(v) for v in iocs.values())

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class='soc-header'>
    <div>
        <div class='soc-header-title'>🛡️ AI SOC Analyst</div>
        <div class='soc-header-sub'>{inv.get('classification','Unknown Classification')} &nbsp;·&nbsp; {severity} Severity</div>
    </div>
    <div style='text-align:right;'>
        {severity_badge(severity)}
        <div style='font-size:11px;color:#45475a;margin-top:6px;'>
            {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Metric Row ────────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("🎯 Risk Score",    f"{risk_score}/100")
m2.metric("📊 Confidence",    f"{confidence}%")
m3.metric("🔎 IOCs Found",    total_iocs)
m4.metric("📅 Events",        len(events))
m5.metric("🗺️ MITRE Techs",  len(mitre))
m6.metric("📋 Actions",       sum(len(resp.get(p,[])) for p in ["containment","eradication","recovery","remediation"]))

# ── Decision Banner ───────────────────────────────────────────────────────────
st.markdown(decision_box(decision), unsafe_allow_html=True)

# ── Export Row ────────────────────────────────────────────────────────────────
exp1, exp2, exp3 = st.columns([1, 1, 4])
md_report = build_markdown_report()
exp1.download_button(
    "⬇️ Export Markdown",
    data=md_report,
    file_name="soc_report.md",
    mime="text/markdown",
    use_container_width=True,
)
json_report = json.dumps({
    "investigation": inv, "risk": risk, "iocs": iocs,
    "mitre": mitre, "response": resp
}, indent=2)
exp2.download_button(
    "⬇️ Export JSON",
    data=json_report,
    file_name="soc_investigation.json",
    mime="application/json",
    use_container_width=True,
)

st.markdown("<hr class='divider'>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
tab_overview, tab_invest, tab_timeline, tab_ioc, tab_mitre, tab_response, tab_evidence = st.tabs([
    "📊 Overview",
    "🔎 Investigation",
    "🧭 Timeline",
    "🧩 IOCs",
    "🗺️ MITRE ATT&CK",
    "🛡️ Response",
    "📂 Evidence",
])


# ── TAB: Overview ─────────────────────────────────────────────────────────────
with tab_overview:
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("#### 📋 Executive Summary")
        st.markdown(f"""
        <div style='background:#0d1526;border:1px solid #1e2d4a;border-radius:8px;padding:16px 20px;
                    font-size:14px;line-height:1.7;color:#cdd6f4;'>
            {inv.get("summary", "No summary generated.")}
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### ⚠️ Risk Factors")
        for factor in risk.get("factors", []):
            st.markdown(f"<div style='color:#a6adc8;font-size:13px;padding:4px 0;'>▸ {factor}</div>",
                        unsafe_allow_html=True)

    with col_right:
        st.markdown("#### 🎯 Severity Gauge")
        bar_color = "#f38ba8" if severity == "Critical" else \
                    "#fab387" if severity == "High" else \
                    "#f9e2af" if severity == "Medium" else "#a6e3a1"

        st.markdown(f"""
        <div style='background:#0d1526;border:1px solid #1e2d4a;border-radius:10px;padding:20px;text-align:center;'>
            <div style='font-size:52px;font-weight:700;color:{bar_color};line-height:1;'>{risk_score}</div>
            <div style='font-size:13px;color:#6c7086;margin:4px 0 12px 0;'>Risk Score / 100</div>
            <div style='background:#11182b;border-radius:8px;height:10px;overflow:hidden;'>
                <div style='width:{risk_score}%;height:100%;background:{bar_color};border-radius:8px;'></div>
            </div>
            <div style='margin-top:12px;'>{severity_badge(severity)}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 🏷️ Classification")
        st.markdown(f"""
        <div style='background:#0d1526;border:1px solid #1e2d4a;border-radius:8px;padding:14px 18px;'>
            <div style='font-size:16px;font-weight:600;color:#cdd6f4;'>{inv.get("classification","N/A")}</div>
            <div style='font-size:13px;color:#6c7086;margin-top:4px;'>Confidence: {confidence}%</div>
        </div>
        """, unsafe_allow_html=True)


# ── TAB: Investigation ────────────────────────────────────────────────────────
with tab_invest:
    st.markdown("#### 🔎 Investigation Findings")
    findings = inv.get("findings", [])
    if findings:
        for i, finding in enumerate(findings, 1):
            st.markdown(f"""
            <div style='background:#0d1526;border:1px solid #1e2d4a;border-left:3px solid #74c7ec;
                        border-radius:8px;padding:12px 18px;margin-bottom:8px;font-size:13px;color:#cdd6f4;'>
                <b style='color:#74c7ec;'>#{i}</b> &nbsp; {finding}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No findings generated.")

    st.markdown("---")
    st.markdown("#### 🧠 Root Cause Analysis")
    rc = inv.get("root_cause", {})
    if rc:
        col_rc1, col_rc2, col_rc3 = st.columns([2, 3, 1])
        col_rc1.markdown(f"""
        <div class='stat-card'>
            <div style='font-size:13px;font-weight:700;color:#f9e2af;'>Root Cause</div>
            <div style='font-size:13px;color:#cdd6f4;margin-top:6px;'>{rc.get("cause","N/A")}</div>
        </div>
        """, unsafe_allow_html=True)
        col_rc2.markdown(f"""
        <div class='stat-card'>
            <div style='font-size:13px;font-weight:700;color:#74c7ec;'>Evidence</div>
            <div style='font-size:13px;color:#a6adc8;margin-top:6px;'>{rc.get("evidence","N/A")}</div>
        </div>
        """, unsafe_allow_html=True)
        col_rc3.markdown(f"""
        <div class='stat-card'>
            <div style='font-size:13px;font-weight:700;color:#a6e3a1;'>Confidence</div>
            <div style='font-size:22px;font-weight:700;color:#cdd6f4;margin-top:6px;'>{rc.get("confidence","N/A")}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### ⚠️ Additional Evidence Required")
    add_ev = inv.get("additional_evidence_required", [])
    if add_ev:
        for ev in add_ev:
            st.markdown(f"<div style='color:#f9e2af;font-size:13px;padding:3px 0;'>⚠️ {ev}</div>",
                        unsafe_allow_html=True)
    else:
        st.success("No additional evidence flagged.")


# ── TAB: Timeline ─────────────────────────────────────────────────────────────
with tab_timeline:
    st.markdown("#### 🧭 Attack Timeline")
    timeline = inv.get("timeline", [])
    if timeline:
        total = len(timeline)
        html = "<div style='padding: 8px 0;'>"
        for i, event in enumerate(timeline):
            dot_cls = timeline_dot_color(i, total)
            html += f"""
            <div class='timeline-item'>
                <div class='timeline-dot {dot_cls}'></div>
                <div class='timeline-text'>{event}</div>
            </div>
            """
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)
    else:
        st.info("No timeline events generated.")


# ── TAB: IOCs ─────────────────────────────────────────────────────────────────
with tab_ioc:
    st.markdown("#### 🧩 Indicators of Compromise")

    if not iocs:
        st.info("No IOCs extracted.")
    else:
        # Summary row
        ioc_cols = st.columns(len(iocs))
        for i, (ioc_type, values) in enumerate(iocs.items()):
            ioc_cols[i].markdown(f"""
            <div class='stat-card'>
                <div class='stat-card-value'>{len(values)}</div>
                <div class='stat-card-label'>{ioc_type.upper()}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Full IOC table
        rows = []
        for ioc_type, values in iocs.items():
            for v in values:
                rows.append({"Type": ioc_type.upper(), "Indicator": v})
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            # CSV export
            csv = df.to_csv(index=False)
            st.download_button("⬇️ Export IOCs (CSV)", data=csv,
                               file_name="iocs.csv", mime="text/csv")


# ── TAB: MITRE ATT&CK ────────────────────────────────────────────────────────
with tab_mitre:
    st.markdown("#### 🗺️ MITRE ATT&CK Technique Mapping")
    if not mitre:
        st.info("No MITRE techniques mapped.")
    else:
        for tech in mitre:
            conf = str(tech.get("confidence", "")).lower()
            badge_color = "#f38ba8" if conf == "high" else \
                          "#f9e2af" if conf == "medium" else "#a6e3a1"
            st.markdown(f"""
            <div class='mitre-card'>
                <div>
                    <span class='mitre-id'>{tech.get("technique_id","N/A")}</span>
                    <span class='mitre-name'>{tech.get("technique_name","N/A")}</span>
                    <span style='float:right;padding:2px 10px;border-radius:12px;font-size:11px;
                                 font-weight:700;background:rgba(0,0,0,0.3);color:{badge_color};
                                 border:1px solid {badge_color};'>
                        {tech.get("confidence","N/A")} Confidence
                    </span>
                </div>
                <div class='mitre-evidence'>Evidence: {tech.get("evidence","N/A")}</div>
            </div>
            """, unsafe_allow_html=True)


# ── TAB: Response ─────────────────────────────────────────────────────────────
with tab_response:
    st.markdown("#### 🛡️ Incident Response Playbook")
    if not resp or "error" in resp:
        st.error("Playbook generation failed or no response data.")
    else:
        phase_icons = {
            "containment":  ("🔒", "#f38ba8"),
            "eradication":  ("🧹", "#fab387"),
            "recovery":     ("♻️", "#a6e3a1"),
            "remediation":  ("🔧", "#74c7ec"),
        }
        for phase, (icon, color) in phase_icons.items():
            actions = resp.get(phase, [])
            if not actions:
                continue
            st.markdown(f"""
            <div style='font-size:15px;font-weight:700;color:{color};
                        margin:16px 0 8px 0;padding-bottom:4px;
                        border-bottom:1px solid #1e2d4a;'>
                {icon} {phase.capitalize()} Actions ({len(actions)})
            </div>
            """, unsafe_allow_html=True)

            for action in actions:
                requires = action.get("requires_approval", "YES")
                approval_html = (
                    '<span class="approval-badge">⚠️ REQUIRES APPROVAL</span>'
                    if str(requires).upper() == "YES"
                    else '<span class="readonly-badge">✅ READ-ONLY</span>'
                )
                st.markdown(f"""
                <div class='playbook-action'>
                    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;'>
                        <div class='playbook-action-title'>{action.get("action","N/A")}</div>
                        {approval_html}
                    </div>
                    <div style='font-size:12px;color:#6c7086;margin-bottom:8px;'>
                        <b>Target:</b> {action.get("target","N/A")} &nbsp;|&nbsp;
                        <b>Risk:</b> {action.get("risk","N/A")} &nbsp;|&nbsp;
                        <b>Reason:</b> {action.get("reason","N/A")}
                    </div>
                """, unsafe_allow_html=True)
                cmd = action.get("command_example", "")
                if cmd:
                    st.code(cmd, language="bash")
                st.markdown("</div>", unsafe_allow_html=True)


# ── TAB: Evidence ─────────────────────────────────────────────────────────────
with tab_evidence:
    st.markdown("#### 📂 Raw Ingested Events")
    show_count = st.slider("Show events", 5, min(200, len(events)), 20)
    st.json(events[:show_count])
    if len(events) > show_count:
        st.caption(f"Showing {show_count} of {len(events)} total events.")

    st.markdown("---")
    with st.expander("📝 Raw Log Text"):
        st.text(st.session_state.raw_logs[:5000] if st.session_state.raw_logs else "No raw logs.")
