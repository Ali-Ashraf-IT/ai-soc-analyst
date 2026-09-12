import streamlit as st
import json
import pandas as pd
import datetime
import plotly.graph_objects as go
import plotly.express as px

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
    page_title="AI SOC Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Exabeam / QRadar inspired dark theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Reset & Base ── */
*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
.stApp { background: #0b0f1e !important; }
.main .block-container { padding: 0 1.5rem 2rem 1.5rem; max-width: 100%; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0b0f1e; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #080c18 !important;
    border-right: 1px solid #162035;
    min-width: 270px !important;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0; }
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span { color: #cbd5e1 !important; font-size: 12px !important; font-weight: 600 !important; }
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 { color: #f8fafc !important; font-weight: 600 !important; }
[data-testid="stSidebar"] .stTextInput > label,
[data-testid="stSidebar"] .stTextArea > label,
[data-testid="stSidebar"] .stFileUploader > label { color: #cbd5e1 !important; font-size: 11px !important; font-weight: 600 !important; text-transform: uppercase; letter-spacing: 0.06em; }
[data-testid="stSidebar"] .stTextInput input,
[data-testid="stSidebar"] .stTextArea textarea {
    background: #101624 !important;
    border: 1px solid #1e3050 !important;
    color: #f8fafc !important;
    border-radius: 5px !important;
    font-size: 13px !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] .stTextInput input:focus,
[data-testid="stSidebar"] .stTextArea textarea:focus {
    border-color: #3b7dd8 !important;
    box-shadow: 0 0 0 2px rgba(59,125,216,0.2) !important;
}

/* ── Buttons ── */
.stButton > button {
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 8px 16px !important;
    transition: all 0.18s ease !important;
    border: none !important;
    cursor: pointer !important;
    letter-spacing: 0.02em !important;
}
/* Primary investigate button */
[data-testid="stSidebar"] .stButton:first-of-type > button {
    background: linear-gradient(135deg, #1a56db, #1e40af) !important;
    color: #ffffff !important;
    box-shadow: 0 2px 8px rgba(26,86,219,0.4) !important;
    width: 100% !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] .stButton:first-of-type > button:hover {
    background: linear-gradient(135deg, #1d4ed8, #1e3a8a) !important;
    box-shadow: 0 4px 16px rgba(26,86,219,0.5) !important;
    transform: translateY(-1px) !important;
}
/* Clear button */
[data-testid="stSidebar"] .stButton:last-of-type > button {
    background: #1a2235 !important;
    color: #cbd5e1 !important;
    border: 1px solid #1e3050 !important;
    width: 100% !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] .stButton:last-of-type > button:hover {
    background: #1f2940 !important;
    color: #ffffff !important;
    border-color: #3b5a8a !important;
}
/* Download buttons in main area */
.main .stDownloadButton > button {
    background: #101624 !important;
    color: #3b9eff !important;
    border: 1px solid #1e3a5f !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    padding: 6px 14px !important;
}
.main .stDownloadButton > button:hover {
    background: #162035 !important;
    color: #60b4ff !important;
    border-color: #3b7dd8 !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #0e1525;
    border-bottom: 2px solid #1e2d4a;
    padding: 0 4px;
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #cbd5e1 !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    padding: 11px 20px !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    margin-bottom: -2px;
    transition: all 0.15s !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #ffffff !important; background: #141d33 !important; }
.stTabs [aria-selected="true"] {
    color: #60a5fa !important;
    border-bottom: 2px solid #3b9eff !important;
    font-weight: 700 !important;
}
.stTabs [data-baseweb="tab-panel"] { padding: 20px 0 0 0; background: transparent; }

/* ── Native Metrics — hide, we use custom HTML cards ── */
[data-testid="stMetric"] { display: none; }

/* ── Expander ── */
[data-testid="stExpander"] {
    background: #0e1525 !important;
    border: 1px solid #1e2d4a !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] summary {
    color: #cbd5e1 !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    padding: 10px 16px !important;
}
[data-testid="stExpander"] summary:hover { color: #ffffff !important; }

/* ── DataFrame ── */
.stDataFrame { border: 1px solid #1e2d4a !important; border-radius: 8px !important; overflow: hidden; }
.stDataFrame thead th {
    background: #0e1525 !important;
    color: #cbd5e1 !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    border-bottom: 1px solid #1e2d4a !important;
}
.stDataFrame tbody td { background: #0b0f1e !important; color: #f8fafc !important; font-size: 13px !important; font-weight: 600 !important; border-bottom: 1px solid #0e1525 !important; }
.stDataFrame tbody tr:hover td { background: #0e1525 !important; }

/* ── Code ── */
.stCodeBlock > div { background: #0a0e1c !important; border: 1px solid #1e2d4a !important; border-radius: 6px !important; }
code { font-family: 'JetBrains Mono', monospace !important; color: #a8d8a8 !important; font-size: 12px !important; font-weight: 600 !important; }

/* ── Progress bar ── */
.stProgress { margin: 4px 0; }
.stProgress > div > div { background: #3b9eff !important; border-radius: 2px !important; }

/* ── Alerts & Messages ── */
.stAlert { border-radius: 6px !important; border-left-width: 3px !important; font-size: 13px !important; font-weight: 600 !important; }
.stInfo { background: #0a1628 !important; border-color: #1a56db !important; color: #8bb8ff !important; }
.stSuccess { background: #051a12 !important; border-color: #16a34a !important; color: #6ee09a !important; }
.stError { background: #1a080a !important; border-color: #dc2626 !important; color: #fca5a5 !important; }
.stWarning { background: #1a1208 !important; border-color: #d97706 !important; color: #fcd34d !important; }

/* ── File Uploader ── */
[data-testid="stFileUploader"] {
    border: 1px dashed #1e3050 !important;
    border-radius: 6px !important;
    background: #0a0e1c !important;
    padding: 8px !important;
}

/* ── Slider ── */
.stSlider [data-baseweb="slider"] { background: #1e3050 !important; }

/* ── JSON viewer ── */
.stJson { background: #0a0e1c !important; border: 1px solid #162035 !important; border-radius: 6px !important; }

/* ─── CUSTOM COMPONENT STYLES ─── */

.soc-topbar {
    background: linear-gradient(90deg, #090e1d 0%, #0d1528 40%, #0a1020 100%);
    border-bottom: 1px solid #162035;
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 0 -1.5rem 24px -1.5rem;
}
.soc-logo { display: flex; align-items: center; gap: 10px; }
.soc-logo-icon { font-size: 26px; }
.soc-logo-text { font-size: 17px; font-weight: 700; color: #ffffff; letter-spacing: -0.01em; }
.soc-logo-sub  { font-size: 11px; color: #cbd5e1; margin-top: 1px; font-weight: 600; }
.soc-topbar-right { display: flex; align-items: center; gap: 20px; font-size: 12px; color: #cbd5e1; font-weight: 600; }
.soc-status-dot { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; display: inline-block; margin-right: 5px; box-shadow: 0 0 5px #22c55e; }

.metric-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 16px; }
.metric-card {
    background: #0e1525;
    border: 1px solid #1e2d4a;
    border-radius: 8px;
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 8px 8px 0 0;
}
.metric-card:hover { border-color: #3b7dd8; }
.metric-card.accent-blue::before { background: #1a56db; }
.metric-card.accent-red::before { background: #dc2626; }
.metric-card.accent-amber::before { background: #d97706; }
.metric-card.accent-green::before { background: #16a34a; }
.metric-card.accent-purple::before { background: #7c3aed; }
.metric-card.accent-cyan::before { background: #0891b2; }
.metric-card-icon { font-size: 18px; margin-bottom: 8px; }
.metric-card-value { font-size: 30px; font-weight: 800; color: #ffffff; line-height: 1; letter-spacing: -0.02em; }
.metric-card-label { font-size: 11px; color: #cbd5e1; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; margin-top: 5px; }
.metric-card-sub { font-size: 11px; color: #60a5fa; margin-top: 3px; font-weight: 600; }

.sev-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 5px 14px; border-radius: 4px;
    font-size: 12px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
}
.sev-CRITICAL { background: rgba(220,38,38,0.15); color: #f87171; border: 1px solid rgba(220,38,38,0.35); }
.sev-HIGH     { background: rgba(217,119,6,0.15);  color: #fbbf24; border: 1px solid rgba(217,119,6,0.35); }
.sev-MEDIUM   { background: rgba(234,179,8,0.12);  color: #facc15; border: 1px solid rgba(234,179,8,0.3); }
.sev-LOW      { background: rgba(22,163,74,0.12);  color: #4ade80; border: 1px solid rgba(22,163,74,0.3); }
.sev-FP       { background: rgba(59,154,255,0.12); color: #60a5fa; border: 1px solid rgba(59,154,255,0.3); }

.decision-banner {
    border-radius: 7px;
    padding: 14px 22px;
    font-size: 14px;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
    letter-spacing: 0.03em;
}
.db-tp       { background: rgba(220,38,38,0.1);  border: 1px solid rgba(220,38,38,0.3);  color: #f87171; }
.db-incident { background: rgba(217,119,6,0.1);  border: 1px solid rgba(217,119,6,0.3);  color: #fbbf24; }
.db-fp       { background: rgba(22,163,74,0.1);  border: 1px solid rgba(22,163,74,0.3);  color: #4ade80; }
.db-susp     { background: rgba(234,179,8,0.1);  border: 1px solid rgba(234,179,8,0.3);  color: #facc15; }
.db-benign   { background: rgba(59,154,255,0.1); border: 1px solid rgba(59,154,255,0.3); color: #60a5fa; }

.widget {
    background: #0e1525;
    border: 1px solid #1e2d4a;
    border-radius: 8px;
    padding: 0;
    overflow: hidden;
    margin-bottom: 14px;
}
.widget-header {
    background: #0a1020;
    border-bottom: 1px solid #1e2d4a;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.widget-title { font-size: 12px; font-weight: 600; color: #e2e8f0; text-transform: uppercase; letter-spacing: 0.07em; }
.widget-body { padding: 16px; color: #f8fafc; font-weight: 600; line-height: 1.75; font-size: 13px; }

.finding-row {
    display: flex; align-items: flex-start; gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid #162035;
    font-size: 13px; color: #f8fafc; font-weight: 600;
}
.finding-row:last-child { border-bottom: none; }
.finding-num { color: #3b9eff; font-weight: 700; font-size: 11px; min-width: 22px; padding-top: 2px; }

.tl-row { display: flex; align-items: flex-start; gap: 14px; padding: 9px 0; border-bottom: 1px solid #162035; }
.tl-row:last-child { border-bottom: none; }
.tl-connector { display: flex; flex-direction: column; align-items: center; gap: 0; }
.tl-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; margin-top: 3px; }
.tl-line { width: 1px; background: #1e2d4a; flex: 1; min-height: 10px; }
.tl-text { font-size: 13px; color: #f8fafc; font-weight: 600; font-family: 'JetBrains Mono', monospace; line-height: 1.5; }

.ioc-type-badge {
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-size: 10px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; margin-right: 4px;
}
.ib-ip      { background: rgba(220,38,38,0.15);  color: #f87171; }
.ib-hash    { background: rgba(124,58,237,0.15); color: #c084fc; }
.ib-domain  { background: rgba(8,145,178,0.15);  color: #22d3ee; }
.ib-user    { background: rgba(234,179,8,0.15);  color: #facc15; }
.ib-process { background: rgba(22,163,74,0.15);  color: #4ade80; }
.ib-email   { background: rgba(217,119,6,0.15);  color: #fbbf24; }

.mitre-row {
    background: #0b0f1e;
    border: 1px solid #1e2d4a;
    border-left: 3px solid #1a56db;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 8px;
}
.mitre-tid   { font-family: 'JetBrains Mono', monospace; color: #3b9eff; font-weight: 700; font-size: 13px; }
.mitre-tname { color: #ffffff; font-weight: 600; font-size: 13px; margin-left: 8px; }
.mitre-ev    { font-size: 12px; color: #cbd5e1; font-weight: 600; margin-top: 5px; }
.conf-high   { color: #f87171; font-size: 11px; font-weight: 700; float: right; background: rgba(220,38,38,0.1); padding: 2px 8px; border-radius: 3px; border: 1px solid rgba(220,38,38,0.25); }
.conf-medium { color: #fbbf24; font-size: 11px; font-weight: 700; float: right; background: rgba(217,119,6,0.1);  padding: 2px 8px; border-radius: 3px; border: 1px solid rgba(217,119,6,0.25); }
.conf-low    { color: #4ade80; font-size: 11px; font-weight: 700; float: right; background: rgba(22,163,74,0.1);  padding: 2px 8px; border-radius: 3px; border: 1px solid rgba(22,163,74,0.25); }

.pb-card {
    background: #0b0f1e;
    border: 1px solid #1e2d4a;
    border-radius: 7px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.pb-card-title { font-size: 14px; font-weight: 600; color: #ffffff; margin-bottom: 6px; }
.pb-meta { font-size: 12px; color: #cbd5e1; font-weight: 600; margin-bottom: 8px; }
.appr-badge { display: inline-block; padding: 2px 9px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: 0.05em; }
.appr-yes { background: rgba(220,38,38,0.15); color: #f87171; border: 1px solid rgba(220,38,38,0.3); }
.appr-ro  { background: rgba(22,163,74,0.12); color: #4ade80; border: 1px solid rgba(22,163,74,0.25); }

.phase-header {
    font-size: 13px; font-weight: 600; color: #e2e8f0;
    text-transform: uppercase; letter-spacing: 0.07em;
    padding: 10px 0 6px 0;
    border-bottom: 1px solid #1e2d4a;
    margin-bottom: 10px;
    display: flex; align-items: center; gap: 8px;
}

.rc-grid { display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 12px; }
.rc-card { background: #0b0f1e; border: 1px solid #1e2d4a; border-radius: 7px; padding: 14px 16px; }
.rc-card-label { font-size: 11px; font-weight: 600; color: #cbd5e1; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 6px; }
.rc-card-value { font-size: 13px; color: #f8fafc; font-weight: 600; line-height: 1.5; }

.steps-panel { background: #0b0f1e; border: 1px solid #1e2d4a; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; }
.steps-title { font-size: 12px; font-weight: 700; color: #3b9eff; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 12px; }
.step-row { display: flex; align-items: center; gap: 10px; padding: 6px 0; font-size: 12px; color: #cbd5e1; font-weight: 600; }
.step-row.s-done   { color: #4ade80; }
.step-row.s-active { color: #3b9eff; font-weight: 600; }

.landing-hero {
    text-align: center;
    padding: 60px 40px;
    background: radial-gradient(ellipse at 50% 0%, rgba(26,86,219,0.12) 0%, transparent 70%);
    border: 1px solid #1e2d4a;
    border-radius: 12px;
    margin-top: 20px;
}
.landing-hero h1 { font-size: 32px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em; margin-bottom: 10px; }
.landing-hero p  { font-size: 15px; color: #cbd5e1; font-weight: 600; margin-bottom: 32px; }
.feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; text-align: left; margin-top: 32px; }
.feature-card {
    background: #0e1525; border: 1px solid #1e2d4a; border-radius: 8px; padding: 18px 20px;
    transition: border-color 0.2s;
}
.feature-card:hover { border-color: #3b7dd8; }
.feature-card-icon { font-size: 22px; margin-bottom: 8px; }
.feature-card-title { font-size: 13px; font-weight: 600; color: #ffffff; margin-bottom: 4px; }
.feature-card-desc  { font-size: 12px; color: #cbd5e1; font-weight: 600; line-height: 1.5; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
def init_state():
    for k, v in {
        "investigation": None, "iocs": None, "events": None, "detected_sources": [],
        "mitre": None, "risk": None, "response": None,
        "raw_logs": None, "pipeline_done": False,
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def sev_badge_html(sev: str) -> str:
    s = str(sev).upper()
    dot = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(s,"🔵")
    cls = {"CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}.get(s,"FP")
    return f'<span class="sev-badge sev-{cls}">{dot} {s}</span>'

def decision_html(decision: str) -> str:
    d = str(decision).lower()
    if "false positive" in d: cls, icon = "db-fp",      "✅"
    elif "incident confirmed" in d: cls, icon = "db-incident", "🔥"
    elif "true positive" in d: cls, icon = "db-tp",      "🚨"
    elif "suspicious" in d:   cls, icon = "db-susp",    "⚠️"
    else:                      cls, icon = "db-benign",  "ℹ️"
    return f'<div class="decision-banner {cls}">{icon} &nbsp; ANALYST DECISION: &nbsp;<span style="color:inherit">{decision.upper()}</span></div>'

def conf_html(conf: str) -> str:
    c = str(conf).lower()
    cls = "conf-high" if c=="high" else "conf-medium" if c=="medium" else "conf-low"
    return f'<span class="{cls}">{conf.upper()}</span>'

def ioc_badge_html(t: str) -> str:
    t2 = t.lower()
    cls = ("ib-ip" if t2 in ("ipv4","ip","ipv6")
           else "ib-hash" if t2 in ("sha256","md5","sha1","hash")
           else "ib-user" if t2 in ("users","user","username")
           else "ib-process" if t2 in ("processes","process")
           else "ib-email" if t2=="email"
           else "ib-domain")
    label = {"ipv4":"IP","sha256":"SHA256","md5":"MD5","sha1":"SHA1",
             "users":"USER","processes":"PROCESS","email":"EMAIL"}.get(t2, t.upper())
    return f'<span class="ioc-type-badge {cls}">{label}</span>'

def tl_dot_color(i, total):
    p = i / max(total-1, 1)
    return ("#f87171" if p > 0.75 else "#fbbf24" if p > 0.5
            else "#facc15" if p > 0.25 else "#4ade80")

def make_gauge(score, severity):
    color = {"Critical":"#f87171","High":"#fbbf24","Medium":"#facc15","Low":"#4ade80"}.get(severity,"#4ade80")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font":{"size":34,"color":color,"family":"Inter"},"suffix":"/100"},
        gauge={
            "axis":{"range":[0,100],"tickcolor":"#1e2d4a","tickfont":{"color":"#5a6a80","size":10}},
            "bar":{"color":color,"thickness":0.25},
            "bgcolor":"#0b0f1e",
            "borderwidth":0,
            "steps":[
                {"range":[0,20],"color":"rgba(22,163,74,0.1)"},
                {"range":[20,50],"color":"rgba(234,179,8,0.1)"},
                {"range":[50,80],"color":"rgba(217,119,6,0.12)"},
                {"range":[80,100],"color":"rgba(220,38,38,0.12)"},
            ],
            "threshold":{"line":{"color":color,"width":3},"thickness":0.8,"value":score},
        }
    ))
    fig.update_layout(
        height=180, margin=dict(l=20,r=20,t=20,b=10),
        paper_bgcolor="#0e1525", plot_bgcolor="#0e1525",
        font={"family":"Inter","color":"#5a6a80"},
    )
    return fig

def make_ioc_pie(iocs):
    labels, values, colors = [], [], []
    color_map = {"ipv4":"#f87171","sha256":"#c084fc","md5":"#c084fc","domain":"#22d3ee",
                 "users":"#facc15","processes":"#4ade80","email":"#fbbf24","sha1":"#c084fc"}
    for t, v in iocs.items():
        if v:
            labels.append(t.upper())
            values.append(len(v))
            colors.append(color_map.get(t.lower(),"#60a5fa"))
    if not labels:
        return None
    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker=dict(colors=colors, line=dict(color="#0b0f1e", width=2)),
        hole=0.55, textfont=dict(size=11, family="Inter"),
        textinfo="label+percent",
    ))
    fig.update_layout(
        height=220, margin=dict(l=10,r=10,t=10,b=10),
        paper_bgcolor="#0e1525", plot_bgcolor="#0e1525",
        font=dict(color="#8892a4", family="Inter"),
        showlegend=False,
    )
    return fig

def make_mitre_bar(mitre):
    if not mitre:
        return None
    ids   = [m.get("technique_id","?") for m in mitre]
    confs = [{"High":3,"Medium":2,"Low":1}.get(m.get("confidence","Low"),1) for m in mitre]
    colors= [{"High":"#f87171","Medium":"#fbbf24","Low":"#4ade80"}.get(m.get("confidence","Low"),"#4ade80") for m in mitre]
    fig = go.Figure(go.Bar(
        x=ids, y=confs,
        marker=dict(color=colors, line=dict(color="#0b0f1e",width=1)),
        text=[m.get("confidence","?") for m in mitre],
        textposition="outside", textfont=dict(size=10,color="#8892a4"),
    ))
    fig.update_layout(
        height=200, margin=dict(l=10,r=10,t=10,b=30),
        paper_bgcolor="#0e1525", plot_bgcolor="#0e1525",
        font=dict(color="#5a6a80",family="Inter"),
        yaxis=dict(showticklabels=False,gridcolor="#0e1525",zeroline=False),
        xaxis=dict(tickfont=dict(size=11,color="#8892a4")),
        bargap=0.3,
    )
    return fig

def build_md_report() -> str:
    inv  = st.session_state.investigation or {}
    risk = st.session_state.risk or {}
    iocs = st.session_state.iocs or {}
    mitre= st.session_state.mitre or []
    resp = st.session_state.response or {}
    ts   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    L = [
        "# 🛡️ AI SOC Analyst — Investigation Report",
        f"**Generated:** {ts}", "",
        "## Alert Classification",
        f"- **Severity:** {risk.get('severity','N/A')}",
        f"- **Risk Score:** {risk.get('score','N/A')}/100",
        f"- **Classification:** {inv.get('classification','N/A')}",
        f"- **Confidence:** {int(float(inv.get('confidence',0))*100)}%",
        f"- **Decision:** {inv.get('decision','N/A')}", "",
        "## Executive Summary", inv.get("summary","N/A"), "",
        "## Findings",
    ]
    for f in inv.get("findings",[]): L.append(f"- {f}")
    L += ["","## Timeline"]
    for t in inv.get("timeline",[]): L.append(f"- {t}")
    L += ["","## IOCs","| Type | Indicator |","|------|-----------|"]
    for t,vs in iocs.items():
        for v in vs: L.append(f"| {t.upper()} | `{v}` |")
    L += ["","## Root Cause"]
    rc = inv.get("root_cause",{})
    L += [f"- **Cause:** {rc.get('cause','N/A')}",
          f"- **Evidence:** {rc.get('evidence','N/A')}",
          f"- **Confidence:** {rc.get('confidence','N/A')}"]
    L += ["","## MITRE ATT&CK","| ID | Technique | Evidence | Confidence |","|----|-----------|----------|------------|"]
    for m in mitre:
        L.append(f"| {m.get('technique_id','?')} | {m.get('technique_name','?')} | {m.get('evidence','?')} | {m.get('confidence','?')} |")
    for ph in ["containment","eradication","recovery","remediation"]:
        L += ["",f"## {ph.capitalize()}"]
        for a in resp.get(ph,[]):
            L.append(f"- **{a.get('action','?')}** — {a.get('reason','?')}")
            L.append(f"  - `{a.get('command_example','?')}` | Risk: {a.get('risk','?')} | Approval: {a.get('requires_approval','YES')}")
    L += ["","## Additional Evidence Required"]
    for e in inv.get("additional_evidence_required",[]): L.append(f"- {e}")
    return "\n".join(L)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:20px 16px 16px;border-bottom:1px solid #162035;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:10px;">
            <span style="font-size:28px;">🛡️</span>
            <div>
                <div style="font-size:15px;font-weight:800;color:#e2e8f4;letter-spacing:-0.01em;">AI SOC Analyst</div>
                <div style="font-size:10px;color:#3b7dd8;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Incident Response Platform</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div style="font-size:10px;font-weight:700;color:#5a6a80;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">LLM Configuration</div>', unsafe_allow_html=True)
    api_key  = st.text_input("API Key", type="password", placeholder="gsk_... or sk-or-...")
    base_url = st.text_input("Base URL", value="https://api.groq.com/openai/v1")
    model    = st.text_input("Model", value="llama-3.1-70b-versatile")

    st.markdown('<hr style="border:none;border-top:1px solid #162035;margin:14px 0;">', unsafe_allow_html=True)
    st.markdown('<div style="font-size:10px;font-weight:700;color:#5a6a80;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">Log Ingestion</div>', unsafe_allow_html=True)

    uploaded_files = st.file_uploader("Upload Files", accept_multiple_files=True,
                                       type=["txt","log","csv","json"])
    raw_logs_text = st.text_area("Paste Raw Logs", height=140,
                                  placeholder="Paste any log format here…\nWindows Event / Sysmon / Firewall / Auth / IDS / DNS…")

    st.markdown('<hr style="border:none;border-top:1px solid #162035;margin:14px 0;">', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    start_btn = c1.button("🔍 Investigate", type="primary", use_container_width=True)
    clear_btn = c2.button("🗑️ Clear", use_container_width=True)

    if clear_btn:
        st.session_state.clear(); init_state(); st.rerun()

    st.markdown("""
    <hr style="border:none;border-top:1px solid #162035;margin:14px 0;">
    <div style="font-size:10px;color:#37404f;line-height:1.8;">
        <span style="color:#5a6a80;font-weight:700;">Supported Log Types</span><br>
        Windows Events · Sysmon · Defender<br>
        Firewall · VPN · Auth · Linux Auth<br>
        EDR · IDS/IPS · DNS · Proxy · Web
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
def run_pipeline():
    if not api_key:
        st.error("⚠️  Enter your LLM API Key in the sidebar to start."); return

    raw = raw_logs_text or ""
    if uploaded_files:
        for f in uploaded_files:
            try: raw += "\n" + f.getvalue().decode("utf-8", errors="ignore")
            except Exception as e: st.warning(f"Could not read {f.name}: {e}")
    if not raw.strip():
        st.error("No logs provided. Upload a file or paste raw logs."); return

    st.session_state.raw_logs = raw
    stages = [
        ("📂","Parsing & normalizing logs"),
        ("🔎","Extracting IOCs"),
        ("🤖","AI investigation — stage analysis"),
        ("🗺️","Mapping MITRE ATT&CK techniques"),
        ("📊","Calculating risk score"),
        ("📋","Generating IR playbook"),
    ]
    prog = st.empty()

    def show_prog(done):
        rows = ""
        for i,(icon,label) in enumerate(stages):
            if i < done:   rows += f'<div class="step-row s-done">✅ {label}</div>'
            elif i == done: rows += f'<div class="step-row s-active">{icon} <b>{label}…</b></div>'
            else:           rows += f'<div class="step-row">{icon} {label}</div>'
        prog.markdown(f'<div class="steps-panel"><div class="steps-title">🔄 Investigation Pipeline Running</div>{rows}</div>',
                      unsafe_allow_html=True)

    try:
        show_prog(0)
        parsed = LogParser.parse_logs(raw)
        events = parsed["events"]
        detected_sources = parsed["detected_sources"]
        st.session_state.events = events
        st.session_state.detected_sources = detected_sources

        show_prog(1)
        iocs = IOCExtractor.extract(events)
        st.session_state.iocs = iocs

        show_prog(2)
        client = LLMClient(api_key=api_key, base_url=base_url, model=model)
        inv = Investigator(client).investigate(events[:80], iocs, detected_sources)
        if "error" in inv:
            prog.empty(); st.error(f"AI Error: {inv['error']}"); return
        st.session_state.investigation = inv

        show_prog(3)
        st.session_state.mitre = MitreMapper(client).map_to_mitre(inv, events[:80])

        show_prog(4)
        st.session_state.risk = RiskEngine.calculate_risk(inv, iocs)

        show_prog(5)
        st.session_state.response = ResponseEngine(client).generate_playbook(inv, iocs, detected_sources)

        st.session_state.pipeline_done = True
        prog.empty(); st.rerun()

    except Exception as e:
        prog.empty(); st.error(f"Pipeline Error: {e}")


if start_btn:
    run_pipeline()


# ─────────────────────────────────────────────────────────────────────────────
# LANDING
# ─────────────────────────────────────────────────────────────────────────────
if not st.session_state.pipeline_done:
    # Top bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-logo">
            <span class="soc-logo-icon">🛡️</span>
            <div>
                <div class="soc-logo-text">AI SOC Analyst</div>
                <div class="soc-logo-sub">Incident Response &amp; Threat Investigation Platform</div>
            </div>
        </div>
        <div class="soc-topbar-right">
            <span><span class="soc-status-dot"></span>System Ready</span>
            <span>No Active Investigation</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="landing-hero">
        <h1>Automated SOC Investigation</h1>
        <p>Upload security logs and let the AI perform a complete Tier-3 SOC analysis —<br>
        from raw logs to MITRE ATT&CK mapping and Incident Response playbook.</p>
        <div class="feature-grid">
            <div class="feature-card">
                <div class="feature-card-icon">🔎</div>
                <div class="feature-card-title">Agentic Investigation</div>
                <div class="feature-card-desc">5-stage AI analysis pipeline: alert validation, IOC analysis, timeline, correlation, attack detection.</div>
            </div>
            <div class="feature-card">
                <div class="feature-card-icon">🗺️</div>
                <div class="feature-card-title">MITRE ATT&CK Mapping</div>
                <div class="feature-card-desc">Evidence-based technique identification. No keyword guessing — every mapping has log evidence.</div>
            </div>
            <div class="feature-card">
                <div class="feature-card-icon">🛡️</div>
                <div class="feature-card-title">IR Playbook Generation</div>
                <div class="feature-card-desc">Full containment, eradication, recovery and remediation plan — with analyst approval gates on all actions.</div>
            </div>
            <div class="feature-card">
                <div class="feature-card-icon">🧩</div>
                <div class="feature-card-title">IOC Extraction</div>
                <div class="feature-card-desc">Auto-extract IPs, hashes, domains, users, processes from any log format.</div>
            </div>
            <div class="feature-card">
                <div class="feature-card-icon">📊</div>
                <div class="feature-card-title">Risk Scoring</div>
                <div class="feature-card-desc">0–100 risk score with severity classification and factor breakdown.</div>
            </div>
            <div class="feature-card">
                <div class="feature-card-icon">📥</div>
                <div class="feature-card-title">Multi-Format Input</div>
                <div class="feature-card-desc">Supports .txt .log .csv .json and paste. Works with Windows Events, Sysmon, Firewall, Auth, EDR, and more.</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD — DATA
# ─────────────────────────────────────────────────────────────────────────────
inv    = st.session_state.investigation or {}
risk   = st.session_state.risk or {}
iocs   = st.session_state.iocs or {}
mitre  = st.session_state.mitre or []
resp   = st.session_state.response or {}
events = st.session_state.events or []

severity   = risk.get("severity","Unknown")
risk_score = risk.get("score", 0)
confidence = int(float(inv.get("confidence", 0)) * 100)
decision   = inv.get("decision","UNKNOWN")
total_iocs = sum(len(v) for v in iocs.values())
total_acts = sum(len(resp.get(p,[])) for p in ["containment","eradication","recovery","remediation"])

# ── Top Bar ──
ts_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
det_srcs = st.session_state.detected_sources or ["Generic Security Log"]
src_badges = " ".join(f'<span style="background:rgba(59,154,255,0.15);color:#60a5fa;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;border:1px solid rgba(59,154,255,0.3);">💻 {s}</span>' for s in det_srcs)

st.markdown(f"""
<div class="soc-topbar">
    <div class="soc-logo">
        <span class="soc-logo-icon">🛡️</span>
        <div>
            <div class="soc-logo-text">AI SOC Analyst</div>
            <div class="soc-logo-sub">{inv.get('classification','Unknown Classification')}</div>
        </div>
    </div>
    <div class="soc-topbar-right">
        <div>{src_badges}</div>
        <span>{sev_badge_html(severity)}</span>
        <span style="color:#cbd5e1;font-weight:600">{ts_now}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Decision Banner ──
st.markdown(decision_html(decision), unsafe_allow_html=True)

# ── 6-Metric Row ──
m = [
    ("accent-red",    "🎯", str(risk_score), "/100", "Risk Score"),
    ("accent-amber",  "📊", f"{confidence}%", "",    "AI Confidence"),
    ("accent-purple", "🧩", str(total_iocs),  "",    "IOCs Extracted"),
    ("accent-blue",   "📋", str(len(events)), "",    "Log Events"),
    ("accent-cyan",   "🗺️", str(len(mitre)),  "",    "MITRE Techniques"),
    ("accent-green",  "🛡️", str(total_acts),  "",    "Response Actions"),
]
cols = st.columns(6)
for col, (accent, icon, val, suf, label) in zip(cols, m):
    col.markdown(f"""
    <div class="metric-card {accent}">
        <div class="metric-card-icon">{icon}</div>
        <div class="metric-card-value">{val}<span style="font-size:14px;color:#5a6a80">{suf}</span></div>
        <div class="metric-card-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)

# ── Export Row ──
st.markdown("<div style='margin:12px 0 4px 0;'>", unsafe_allow_html=True)
ec1, ec2, ec3 = st.columns([1,1,5])
ec1.download_button("⬇️ Markdown Report", data=build_md_report(),
                    file_name="soc_report.md", mime="text/markdown", use_container_width=True)
ec2.download_button("⬇️ JSON Export",
                    data=json.dumps({"investigation":inv,"risk":risk,"iocs":iocs,"mitre":mitre,"response":resp},indent=2),
                    file_name="soc_investigation.json", mime="application/json", use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div style='margin:8px 0;'>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
t1,t2,t3,t4,t5,t6,t7 = st.tabs([
    "📊  Overview", "🔎  Investigation", "🧭  Timeline",
    "🧩  IOCs", "🗺️  MITRE ATT&CK", "🛡️  Response", "📂  Evidence",
])


# ── TAB 1: Overview ──────────────────────────────────────────────────────────
with t1:
    left, right = st.columns([3, 2])

    with left:
        # Executive Summary widget
        st.markdown(f"""
        <div class="widget">
            <div class="widget-header">
                <span class="widget-title">📋 Executive Summary</span>
                <span style="font-size:10px;color:#3b7dd8;">MANAGEMENT BRIEF</span>
            </div>
            <div class="widget-body" style="font-size:14px;color:#f8fafc;font-weight:600;line-height:1.8;">
                {inv.get("summary","No summary available.")}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Risk Factors widget
        factors = risk.get("factors", [])
        rows = "".join(
            f'<div class="finding-row"><span class="finding-num">▸</span>{f}</div>'
            for f in factors
        ) or '<div style="color:#5a6a80;font-size:13px;padding:8px 0;">No risk factors recorded.</div>'
        st.markdown(f"""
        <div class="widget">
            <div class="widget-header">
                <span class="widget-title">⚠️ Risk Factors</span>
            </div>
            <div class="widget-body">{rows}</div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        # Gauge
        st.markdown("""
        <div class="widget">
            <div class="widget-header"><span class="widget-title">🎯 Risk Gauge</span></div>
        """, unsafe_allow_html=True)
        st.plotly_chart(make_gauge(risk_score, severity), use_container_width=True,
                        config={"displayModeBar":False})
        st.markdown("</div>", unsafe_allow_html=True)

        # Classification card
        st.markdown(f"""
        <div class="widget">
            <div class="widget-header"><span class="widget-title">🏷️ Classification</span></div>
            <div class="widget-body">
                <div style="font-size:17px;font-weight:700;color:#e2e8f4;margin-bottom:6px;">
                    {inv.get('classification','N/A')}
                </div>
                <div style="display:flex;align-items:center;gap:12px;margin-top:8px;">
                    {sev_badge_html(severity)}
                    <span style="font-size:12px;color:#5a6a80;">Confidence: <b style="color:#3b9eff;">{confidence}%</b></span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # IOC pie
        pie = make_ioc_pie(iocs)
        if pie:
            st.markdown("""
            <div class="widget">
                <div class="widget-header"><span class="widget-title">🧩 IOC Distribution</span></div>
            """, unsafe_allow_html=True)
            st.plotly_chart(pie, use_container_width=True, config={"displayModeBar":False})
            st.markdown("</div>", unsafe_allow_html=True)


# ── TAB 2: Investigation ─────────────────────────────────────────────────────
with t2:
    col_f, col_rc = st.columns([3,2])

    with col_f:
        findings = inv.get("findings", [])
        rows = "".join(
            f'<div class="finding-row"><span class="finding-num">#{i}</span>{f}</div>'
            for i,f in enumerate(findings,1)
        ) or '<div style="color:#5a6a80;padding:8px 0;font-size:13px;">No findings generated.</div>'
        st.markdown(f"""
        <div class="widget">
            <div class="widget-header">
                <span class="widget-title">🔎 Investigation Findings</span>
                <span style="font-size:10px;color:#5a6a80;">{len(findings)} findings</span>
            </div>
            <div class="widget-body">{rows}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_rc:
        rc = inv.get("root_cause", {})
        st.markdown(f"""
        <div class="widget">
            <div class="widget-header"><span class="widget-title">🧠 Root Cause Analysis</span></div>
            <div class="widget-body">
                <div class="rc-grid">
                    <div class="rc-card">
                        <div class="rc-card-label">Confidence</div>
                        <div style="font-size:18px;font-weight:800;color:#e2e8f4;">{rc.get('confidence','N/A')}</div>
                    </div>
                    <div class="rc-card" style="grid-column:span 2;">
                        <div class="rc-card-label">Root Cause</div>
                        <div class="rc-card-value">{rc.get('cause','Not determined')}</div>
                    </div>
                    <div class="rc-card" style="grid-column:span 3;">
                        <div class="rc-card-label">Supporting Evidence</div>
                        <div class="rc-card-value" style="color:#8892a4;">{rc.get('evidence','Not present in supplied logs.')}</div>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        add_ev = inv.get("additional_evidence_required", [])
        if add_ev:
            rows_ev = "".join(
                f'<div style="font-size:12px;color:#fbbf24;padding:5px 0;border-bottom:1px solid #0e1525;">⚠️ {e}</div>'
                for e in add_ev
            )
            st.markdown(f"""
            <div class="widget" style="margin-top:14px;">
                <div class="widget-header"><span class="widget-title">⚠️ Additional Evidence Needed</span></div>
                <div class="widget-body">{rows_ev}</div>
            </div>
            """, unsafe_allow_html=True)


# ── TAB 3: Timeline ──────────────────────────────────────────────────────────
with t3:
    timeline = inv.get("timeline", [])
    if not timeline:
        st.info("No timeline data generated.")
    else:
        total = len(timeline)
        rows = ""
        for i, ev in enumerate(timeline):
            dc = tl_dot_color(i, total)
            line = "" if i == total-1 else f'<div class="tl-line"></div>'
            rows += f"""
            <div class="tl-row">
                <div class="tl-connector">
                    <div class="tl-dot" style="background:{dc};box-shadow:0 0 5px {dc};"></div>
                    {line}
                </div>
                <div class="tl-text">{ev}</div>
            </div>"""

        st.markdown(f"""
        <div class="widget">
            <div class="widget-header">
                <span class="widget-title">🧭 Attack Timeline</span>
                <span style="font-size:10px;color:#5a6a80;">{total} events</span>
            </div>
            <div class="widget-body">{rows}</div>
        </div>
        """, unsafe_allow_html=True)


# ── TAB 4: IOCs ──────────────────────────────────────────────────────────────
with t4:
    if not iocs:
        st.info("No IOCs extracted from the provided logs.")
    else:
        # Summary cards
        cols_ioc = st.columns(min(len(iocs), 6))
        accent_cycle = ["accent-red","accent-purple","accent-cyan","accent-amber","accent-green","accent-blue"]
        for col, (ioc_type, vals), acc in zip(cols_ioc, iocs.items(), accent_cycle):
            col.markdown(f"""
            <div class="metric-card {acc}">
                <div class="metric-card-value">{len(vals)}</div>
                <div class="metric-card-label">{ioc_type.upper()}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<div style='margin:16px 0 8px 0;'>", unsafe_allow_html=True)

        # Full table
        rows_d = [{"Type": ioc_badge_html(t)+"&nbsp;"+t.upper(), "Indicator": v}
                  for t, vs in iocs.items() for v in vs]
        if rows_d:
            df = pd.DataFrame([{"Type": t.upper(), "Indicator": v}
                                for t, vs in iocs.items() for v in vs])
            st.dataframe(df, use_container_width=True, hide_index=True)
            csv = df.to_csv(index=False)
            st.download_button("⬇️ Export IOCs as CSV", data=csv,
                               file_name="iocs.csv", mime="text/csv")


# ── TAB 5: MITRE ATT&CK ──────────────────────────────────────────────────────
with t5:
    if not mitre:
        st.info("No MITRE ATT&CK techniques mapped.")
    else:
        left_m, right_m = st.columns([2, 3])

        with left_m:
            bar = make_mitre_bar(mitre)
            if bar:
                st.markdown("""
                <div class="widget">
                    <div class="widget-header"><span class="widget-title">📊 Technique Confidence</span></div>
                """, unsafe_allow_html=True)
                st.plotly_chart(bar, use_container_width=True, config={"displayModeBar":False})
                st.markdown("</div>", unsafe_allow_html=True)

        with right_m:
            st.markdown("""
            <div class="widget">
                <div class="widget-header">
                    <span class="widget-title">🗺️ Mapped Techniques</span>
                </div>
                <div class="widget-body">
            """, unsafe_allow_html=True)
            for tech in mitre:
                chtml = conf_html(tech.get("confidence","?"))
                st.markdown(f"""
                <div class="mitre-row">
                    <div>
                        <span class="mitre-tid">{tech.get('technique_id','?')}</span>
                        <span class="mitre-tname">{tech.get('technique_name','?')}</span>
                        {chtml}
                    </div>
                    <div class="mitre-ev">Evidence: {tech.get('evidence','N/A')}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div></div>", unsafe_allow_html=True)


# ── TAB 6: Response ───────────────────────────────────────────────────────────
with t6:
    if not resp or "error" in resp:
        st.error("Playbook generation failed.")
    else:
        phase_cfg = [
            ("containment",  "🔒", "#f87171", "Containment Actions"),
            ("eradication",  "🧹", "#fbbf24", "Eradication Actions"),
            ("recovery",     "♻️", "#4ade80", "Recovery Actions"),
            ("remediation",  "🔧", "#60a5fa", "Remediation Actions"),
        ]
        for phase, icon, color, label in phase_cfg:
            actions = resp.get(phase, [])
            if not actions:
                continue
            st.markdown(f"""
            <div class="phase-header" style="color:{color};">
                {icon} {label}
                <span style="font-size:11px;color:#5a6a80;margin-left:auto;">{len(actions)} actions</span>
            </div>
            """, unsafe_allow_html=True)

            for act in actions:
                req = act.get("requires_approval","YES")
                appr_html = (f'<span class="appr-badge appr-yes">⚠️ REQUIRES APPROVAL</span>'
                             if str(req).upper()=="YES"
                             else f'<span class="appr-badge appr-ro">✅ READ-ONLY</span>')
                st.markdown(f"""
                <div class="pb-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                        <div class="pb-card-title">{act.get('action','N/A')}</div>
                        {appr_html}
                    </div>
                    <div class="pb-meta">
                        <b>Target:</b> {act.get('target','N/A')} &nbsp;|&nbsp;
                        <b>Risk:</b> {act.get('risk','N/A')} &nbsp;|&nbsp;
                        <b>Reason:</b> {act.get('reason','N/A')}
                    </div>
                """, unsafe_allow_html=True)
                cmd = act.get("command_example","")
                if cmd:
                    st.code(cmd, language="bash")
                st.markdown("</div>", unsafe_allow_html=True)


# ── TAB 7: Evidence ───────────────────────────────────────────────────────────
with t7:
    st.markdown("""
    <div class="widget">
        <div class="widget-header"><span class="widget-title">📂 Parsed Log Events</span></div>
    </div>
    """, unsafe_allow_html=True)

    show_n = st.slider("Show events", 5, min(200, max(len(events),5)), min(20, len(events)))
    st.json(events[:show_n])
    if len(events) > show_n:
        st.caption(f"Showing {show_n} of {len(events)} total events.")

    with st.expander("📝 Original Raw Log Text"):
        raw_l = st.session_state.raw_logs or ""
        st.text(raw_l[:8000] + ("\n... (truncated)" if len(raw_l)>8000 else ""))
