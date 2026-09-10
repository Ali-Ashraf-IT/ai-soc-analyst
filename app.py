import streamlit as st
import json
import pandas as pd
from modules.log_parser import LogParser
from modules.ioc_extractor import IOCExtractor
from modules.llm_client import LLMClient
from modules.investigator import Investigator
from modules.mitre_mapper import MitreMapper
from modules.risk_engine import RiskEngine
from modules.response_engine import ResponseEngine

st.set_page_config(page_title="AI SOC Analyst", page_icon="🛡️", layout="wide")

def initialize_session():
    if "investigation" not in st.session_state:
        st.session_state.investigation = None
    if "iocs" not in st.session_state:
        st.session_state.iocs = None
    if "events" not in st.session_state:
        st.session_state.events = None
    if "mitre" not in st.session_state:
        st.session_state.mitre = None
    if "risk" not in st.session_state:
        st.session_state.risk = None
    if "response" not in st.session_state:
        st.session_state.response = None

initialize_session()

st.sidebar.title("🛡️ AI SOC Analyst")
st.sidebar.markdown("---")

api_key = st.sidebar.text_input("LLM API Key", type="password", help="Required: Your Groq/OpenRouter/OpenAI API Key")
base_url = st.sidebar.text_input("Base URL", value="https://api.groq.com/openai/v1", help="Change for OpenRouter or OpenAI")
model = st.sidebar.text_input("Model", value="llama-3.1-70b-versatile", help="E.g., llama-3.1-70b-versatile or openai/gpt-4o-mini")

st.sidebar.markdown("---")
uploaded_files = st.sidebar.file_uploader("Upload Logs", accept_multiple_files=True, type=['txt', 'log', 'csv', 'json'])
raw_logs_text = st.sidebar.text_area("Or Paste Raw Logs")

def process_logs():
    if not api_key:
        st.sidebar.error("Please configure the LLM API Key.")
        return
        
    raw_text = raw_logs_text
    if uploaded_files:
        for file in uploaded_files:
            try:
                raw_text += "\n" + file.getvalue().decode("utf-8")
            except Exception as e:
                st.sidebar.error(f"Failed to read {file.name}: {e}")
                
    if not raw_text.strip():
        st.sidebar.error("No logs provided.")
        return

    with st.spinner("Parsing logs..."):
        events = LogParser.parse_logs(raw_text)
        st.session_state.events = events
        
    with st.spinner("Extracting IOCs..."):
        iocs = IOCExtractor.extract(events)
        st.session_state.iocs = iocs

    with st.spinner("AI is investigating..."):
        try:
            client = LLMClient(api_key=api_key, base_url=base_url, model=model)
            investigator = Investigator(client)
            mitre_mapper = MitreMapper(client)
            response_engine = ResponseEngine(client)
            
            # Limited batch of events to avoid token limits for this demo
            limited_events = events[:100]
            
            st.session_state.investigation = investigator.investigate(limited_events, iocs)
            
            if "error" not in st.session_state.investigation:
                st.session_state.risk = RiskEngine.calculate_risk(st.session_state.investigation, iocs)
                st.session_state.mitre = mitre_mapper.map_to_mitre(st.session_state.investigation, limited_events)
                st.session_state.response = response_engine.generate_playbook(st.session_state.investigation, iocs)
            else:
                st.error(f"Investigation Error: {st.session_state.investigation.get('error')}")
                
        except Exception as e:
            st.error(f"Pipeline failed: {str(e)}")

if st.sidebar.button("Start Investigation", type="primary"):
    process_logs()
    
if st.sidebar.button("Clear Investigation"):
    st.session_state.clear()
    initialize_session()
    st.rerun()

st.title("Investigation Dashboard")

if not st.session_state.investigation:
    st.info("Upload logs and click 'Start Investigation' to begin.")
else:
    inv = st.session_state.investigation
    risk = st.session_state.risk or {}
    
    if "error" in inv:
        st.error("LLM Error occurred. Please check API Key and model settings.")
        st.json(inv)
        st.stop()
        
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "Overview", "Investigation", "Timeline", "IOCs", "MITRE ATT&CK", "Response Playbook", "Raw Evidence"
    ])
    
    with tab1:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Risk Score", f"{risk.get('score', 'N/A')}/100")
        
        severity = risk.get("severity", "Unknown")
        color = "red" if severity == "Critical" else "orange" if severity == "High" else "yellow" if severity == "Medium" else "green"
        col2.markdown(f"### Severity: <span style='color:{color}'>{severity}</span>", unsafe_allow_html=True)
        
        col3.metric("Confidence", f"{inv.get('confidence', 0)*100}%")
        col4.metric("Extracted IOCs", sum(len(v) for v in st.session_state.iocs.values()))
        
        st.subheader("Decision")
        st.success(inv.get('decision', 'N/A'))
        
        st.subheader("Executive Summary")
        st.write(inv.get('summary', ''))
        
    with tab2:
        st.subheader("Investigation Findings")
        for finding in inv.get('findings', []):
            st.markdown(f"- {finding}")
            
        st.subheader("Root Cause Analysis")
        rc = inv.get('root_cause', {})
        st.write(f"**Cause:** {rc.get('cause', '')}")
        st.write(f"**Evidence:** {rc.get('evidence', '')}")
        
    with tab3:
        st.subheader("Attack Timeline")
        for t in inv.get('timeline', []):
            st.markdown(f"⏱️ {t}")
            
    with tab4:
        st.subheader("Indicators of Compromise")
        for ioc_type, iocs in st.session_state.iocs.items():
            if iocs:
                st.write(f"**{ioc_type.upper()}**")
                st.table(pd.DataFrame(iocs, columns=["Indicator"]))
                
    with tab5:
        st.subheader("MITRE ATT&CK Mapping")
        if st.session_state.mitre:
            df = pd.DataFrame(st.session_state.mitre)
            st.table(df)
        else:
            st.info("No MITRE techniques mapped.")
            
    with tab6:
        st.subheader("Incident Response Playbook")
        if st.session_state.response and "error" not in st.session_state.response:
            resp = st.session_state.response
            for phase in ["containment", "eradication", "recovery", "remediation"]:
                if phase in resp:
                    with st.expander(f"{phase.capitalize()} Actions", expanded=True):
                        for action in resp[phase]:
                            st.markdown(f"**Action:** {action.get('action')}")
                            st.code(action.get('command_example', ''), language="bash")
                            st.caption(f"Risk: {action.get('risk')} | Requires Approval: {action.get('requires_approval')}")
                            st.divider()
        else:
            st.error("Playbook generation failed.")
            
    with tab7:
        st.subheader("Raw Extracted Events")
        st.json(st.session_state.events[:50])
        if len(st.session_state.events) > 50:
            st.caption(f"... and {len(st.session_state.events) - 50} more events.")
