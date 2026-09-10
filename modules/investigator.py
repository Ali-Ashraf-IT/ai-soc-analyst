import json
from .llm_client import LLMClient

class Investigator:
    """
    Agentic investigator that prompts the LLM to analyze the evidence.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def investigate(self, events: list[dict], iocs: dict) -> dict:
        """
        Orchestrates the investigation.
        """
        system_prompt = """
You are a senior Tier-3 SOC Analyst. 
Analyze the provided log events and extracted Indicators of Compromise (IOCs).
Identify the attack timeline, correlate entities, and determine the root cause.
Distinguish clearly between Observed Evidence, Inference, Hypothesis, and Recommendations.

Your response must be valid JSON matching this structure:
{
  "classification": "Attack Category (e.g., Credential Attack, Malware, False Positive)",
  "confidence": 0.0 to 1.0,
  "summary": "2 concise sentences suitable for management.",
  "findings": ["finding 1", "finding 2"],
  "timeline": ["time - event description"],
  "root_cause": {
    "cause": "Description of root cause",
    "evidence": "Supporting evidence from logs",
    "confidence": "High/Medium/Low"
  },
  "additional_evidence_required": ["evidence 1", "evidence 2"],
  "decision": "TRUE POSITIVE | FALSE POSITIVE | BENIGN / EXPECTED ACTIVITY | SUSPICIOUS — REQUIRES FURTHER INVESTIGATION | INCIDENT CONFIRMED"
}
"""
        user_prompt = f"""
Extracted IOCs:
{json.dumps(iocs, indent=2)}

Normalized Events:
{json.dumps(events, indent=2)}

Perform a comprehensive analysis.
"""
        # Call LLM
        result = self.llm_client.generate_json(system_prompt, user_prompt)
        return result
