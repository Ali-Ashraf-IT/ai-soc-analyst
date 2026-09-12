import json
from .llm_client import LLMClient

class ResponseEngine:
    """
    Generates incident response playbooks tailored to the detected log sources and operating system environment.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def generate_playbook(self, investigation_result: dict, iocs: dict, detected_sources: list[str] = None) -> dict:
        sources_str = ", ".join(detected_sources) if detected_sources else "Generic Security Log"

        system_prompt = f"""
You are a senior SOC Incident Responder generating an actionable response playbook.
DETECTED LOG SOURCES: {sources_str}

CRITICAL COMMAND STACK INSTRUCTIONS:
- If DETECTED LOG SOURCES includes "Linux Auth / Syslog" or Linux environment: Generate Linux/Bash commands (e.g. `iptables -A INPUT -s IP -j DROP`, `systemctl stop service`, `passwd -l user`, `pkill -u user`).
- If DETECTED LOG SOURCES includes "Windows Event Log" or Windows environment: Generate Windows PowerShell / CMD commands (e.g. `Disable-ADAccount`, `Stop-Process`, `netsh advfirewall add rule`).
- If DETECTED LOG SOURCES includes "Network Firewall": Generate Firewall CLI commands (e.g. `set firewall rule block ip`).
- Match the command syntax strictly to the detected environment.

IMPORTANT SECURITY RULE:
State-changing actions MUST set "requires_approval": "YES".

Your response must be valid JSON in this structure:
{{
  "containment": [
    {{"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}}
  ],
  "eradication": [
    {{"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}}
  ],
  "recovery": [
    {{"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}}
  ],
  "remediation": [
    {{"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}}
  ]
}}
"""
        user_prompt = f"""
Detected Environment / Log Sources: {sources_str}

Investigation Results:
{json.dumps(investigation_result, indent=2)}

IOCs:
{json.dumps(iocs, indent=2)}

Generate the environment-aware incident response playbook.
"""
        result = self.llm_client.generate_json(system_prompt, user_prompt)
        return result
