import json
from .llm_client import LLMClient

class MitreMapper:
    """
    Maps findings and events to MITRE ATT&CK framework using LLM.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def map_to_mitre(self, investigation_result: dict, events: list[dict]) -> list[dict]:
        system_prompt = """
You are an expert in the MITRE ATT&CK framework.
Based on the provided investigation summary and events, map the observed behaviors to MITRE ATT&CK techniques.
Only map techniques if there is clear evidence supporting them.

Your response must be valid JSON containing a list of mappings in this structure:
{
  "mitre_attack": [
    {
      "technique_id": "TXXXX",
      "technique_name": "Name",
      "evidence": "Evidence from logs",
      "confidence": "High/Medium/Low"
    }
  ]
}
"""
        user_prompt = f"""
Investigation Results:
{json.dumps(investigation_result, indent=2)}

Return the JSON mapping.
"""
        result = self.llm_client.generate_json(system_prompt, user_prompt)
        return result.get("mitre_attack", [])
