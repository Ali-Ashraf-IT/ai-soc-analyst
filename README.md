# 🛡️ AI SOC Analyst

**Autonomous Threat Investigation & Incident Response Platform**

AI SOC Analyst turns raw, unstructured security logs into a fully investigated, MITRE ATT&CK-mapped, risk-scored incident report — complete with a ready-to-execute response playbook — in seconds instead of the 30–60 minutes a manual triage normally takes.

Built for the **Pak Angels Generative & Agentic AI Training — Cohort 11 Mid-Term Hackathon**.

---

## 📖 Overview

Security teams are overwhelmed by alert volume, slow manual investigation times, a global cybersecurity skills gap, and inconsistent incident documentation. AI SOC Analyst addresses this by acting as an autonomous Tier-3-level analyst: you provide raw logs, and it independently validates the alert, extracts evidence, reconstructs the attack, maps it to industry-standard frameworks, and proposes a remediation plan — all with a human analyst retaining final approval on every action.

---

## ⚙️ How It Works

The application runs every submitted log through a 6-stage pipeline:

```
Raw Logs → Log Normalizer → IOC Extractor → LLM Agent → Risk Engine → MITRE Mapper → Response Engine → Dashboard
```

1. **Log Normalizer** (`log_parser.py`) — cleans messy raw text into structured events and auto-detects the log source (Windows Event Log, Linux/Syslog, Firewall/IDS, Web Server, or EDR)
2. **IOC Extractor** (`ioc_extractor.py`) — pulls IP addresses, file hashes, domains, usernames, and processes using fixed regex rules. This step never relies on AI, so these facts are always 100% accurate
3. **LLM Agent / Investigator** (`investigator.py`) — reasons over the evidence like a senior analyst: validates whether the alert is real, builds a timeline, correlates events, and determines root cause. Includes a security guardrail that ignores any instructions hidden inside the raw log text itself (prompt-injection protection)
4. **MITRE Mapper** (`mitre_mapper.py`) — matches confirmed findings to official MITRE ATT&CK technique IDs, each backed by cited log evidence and a confidence rating
5. **Risk Engine** (`risk_engine.py`) — calculates a 0–100 risk score and severity label (Low/Medium/High/Critical) from AI confidence, IOC signals, and attack classification
6. **Response Engine** (`response_engine.py`) — generates an environment-aware Incident Response playbook (Containment → Eradication → Recovery → Remediation), matching command syntax to the detected OS/environment, with every state-changing action flagged as requiring analyst approval

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔎 Agentic Investigation | 5-stage AI reasoning: alert validation, IOC analysis, timeline, correlation, root cause |
| 🧩 Rule-Based IOC Extraction | 100% deterministic — never AI-guessed |
| 🗺️ MITRE ATT&CK Mapping | Evidence-cited techniques with High/Medium/Low confidence |
| 📊 Dynamic Risk Scoring | 0–100 score with transparent factor breakdown |
| 🛡️ IR Playbook Generation | Phase-based plan with mandatory approval gates on risky actions |
| 🖥️ Multi-Source Log Detection | Auto-identifies Windows, Linux, Firewall, Web Server, and EDR logs |
| 📥 Multi-Format Input | `.txt`, `.log`, `.csv`, `.json`, or direct paste |
| 📄 Exportable Reports | One-click Markdown and JSON export |

---

## 🧰 Required Tools & Utilities

Before setting up the project, make sure you have:

- **Python 3.9+**
- **pip** (Python package manager)
- **Git** (to clone the repository)
- An **LLM API key** from a Groq-compatible or OpenAI-compatible provider (e.g., [Groq Console](https://console.groq.com/keys)) — required to run investigations
- (Optional) A code editor such as VS Code

**Python libraries used** (installed via `requirements.txt`): `streamlit`, `openai`, `pydantic`, `python-dotenv`, `pandas`, `plotly`

---

## 🔧 Setup Steps

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd ai-soc-analyst
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your LLM credentials**

   Create a `.env` file in the project root:
   ```
   LLM_API_KEY=your_api_key_here
   LLM_BASE_URL=https://api.groq.com/openai/v1
   LLM_MODEL=llama-3.1-70b-versatile
   ```
   *(You can skip this and enter the same values directly in the app's sidebar instead — useful for quick local testing.)*

4. **Run the application**
   ```bash
   streamlit run app.py
   ```

---

## ▶️ How to Use the Application

1. **Open the app** in your browser (Streamlit will auto-launch it, typically at `localhost:8501`)
2. **Enter your LLM API Key**, Base URL, and Model in the sidebar under *LLM Configuration* (skip if already set in `.env`)
3. **Provide your logs** — either:
   - Upload one or more files (`.txt`, `.log`, `.csv`, `.json`) under *Upload Files*, or
   - Paste raw log text directly into the *Paste Raw Logs* box
4. Click **🔍 Investigate** — the pipeline runs live through all 6 stages (a progress tracker shows each step completing)
5. **Review the results** across the 7 dashboard tabs:
   - **Overview** — executive summary, risk gauge, classification, and IOC distribution
   - **Investigation** — detailed findings and root cause analysis
   - **Timeline** — chronological reconstruction of the attack
   - **IOCs** — extracted indicators in a sortable, exportable table
   - **MITRE ATT&CK** — mapped techniques with evidence and confidence
   - **Response** — the full IR playbook, organized by phase
   - **Evidence** — original raw logs and parsed event JSON (for audit/compliance)
6. **Export your report** — use the *Markdown Report* or *JSON Export* buttons to save the full investigation
7. Click **🗑️ Clear** to reset the session and start a new investigation

---

## 🧪 Testing

Sample dummy logs covering firewall, server, login/admin, suspicious activity, and malware scenarios are available in [`test-logs/`](./test-logs) for verifying the full pipeline end-to-end without needing real production data.

---

## 📂 Project Structure

```
ai-soc-analyst/
├── app.py                      # Main Streamlit dashboard
├── requirements.txt
├── modules/
│   ├── log_parser.py           # Normalizes raw logs + detects log source
│   ├── ioc_extractor.py        # Rule-based IOC extraction
│   ├── llm_client.py           # AI provider connection (OpenAI-compatible)
│   ├── investigator.py         # 5-stage AI investigation logic
│   ├── mitre_mapper.py         # MITRE ATT&CK technique mapping
│   ├── risk_engine.py          # Risk scoring logic
│   └── response_engine.py      # IR playbook generation
└── test-logs/                  # Sample dummy logs for testing
```

---

## 🗺️ Roadmap

- **Phase 1 (Current MVP):** Upload-based log analysis
- **Phase 2:** Live Syslog/webhook streaming for continuous monitoring
- **Phase 3:** Proof-of-concept SOAR integration with a single vendor (e.g., firewall or EDR API) + human-confirmed execute workflow, plus local LLM support (Ollama/vLLM)

---

## 👥 Contributors

Built by the team for Pak Angels Cohort 11 Mid-Term Hackathon.

- Ali Ashraf 
- Maryam Abdul Rauf 
- Hasham Khan 
- Safura Sohail 
- Muhammad Usman
- Reyyan Aleem


## ⚠️ Disclaimer

This is a hackathon MVP intended for demonstration and educational purposes. All response playbook commands require manual analyst review and approval before execution in any real environment.
