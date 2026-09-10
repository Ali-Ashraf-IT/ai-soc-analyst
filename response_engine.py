import json
from .llm_client import LLMClient

class ResponseEngine:
    """
    Generates incident response playbooks based on findings.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def generate_playbook(self, investigation_result: dict, iocs: dict) -> dict:
        system_prompt = """
You are a senior SOC Incident Responder.
Based on the investigation results and IOCs, generate a complete incident-response playbook.
IMPORTANT: State-changing commands MUST require analyst approval. Do not suggest automatic execution of destructive actions.

Your response must be valid JSON in this structure:
{
  "containment": [
    {"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}
  ],
  "eradication": [
    {"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}
  ],
  "recovery": [
    {"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}
  ],
  "remediation": [
    {"action": "string", "reason": "string", "target": "string", "command_example": "string", "risk": "High/Medium/Low", "requires_approval": "YES"}
  ]
}
"""
        user_prompt = f"""
Investigation Results:
{json.dumps(investigation_result, indent=2)}

IOCs:
{json.dumps(iocs, indent=2)}

Generate the playbook.
"""
        result = self.llm_client.generate_json(system_prompt, user_prompt)
        return result
