import os
import json
import re
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

def _get_secret(key: str, default: str = None):
    """
    Reads a secret from Streamlit secrets (for cloud) or .env file (for local).
    Falls back to default if neither is available.
    """
    # Try Streamlit secrets first (for Streamlit Cloud deployment)
    try:
        import streamlit as st
        val = st.secrets.get(key)
        if val:
            return val
    except Exception:
        pass
    # Fall back to environment variable / .env file
    return os.getenv(key, default)


def _extract_json_from_text(text: str) -> dict:
    """
    Fallback: extract a JSON object from raw LLM text even if the model
    did not strictly obey json_object response_format.
    """
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find the first {...} block
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Return a structured error if nothing worked
    return {"error": "Could not parse JSON from LLM response", "raw_output": text[:2000]}


class LLMClient:
    """
    OpenAI-compatible LLM client.
    Works with Groq, OpenRouter, OpenAI, or any compatible provider
    by changing LLM_BASE_URL and LLM_API_KEY.
    """

    def __init__(self, api_key: str = None, base_url: str = None, model: str = None):
        self.api_key  = api_key  or _get_secret("LLM_API_KEY")
        self.base_url = base_url or _get_secret("LLM_BASE_URL", "https://api.groq.com/openai/v1")
        self.model    = model    or _get_secret("LLM_MODEL", "llama-3.1-70b-versatile")

        if not self.api_key:
            raise ValueError(
                "LLM_API_KEY is not configured.\n"
                "Local: Copy .env.example → .env and add your key.\n"
                "Streamlit Cloud: Add it under App Settings → Secrets."
            )

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def generate_json(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Calls the LLM and returns a parsed JSON dict.
        Tries response_format=json_object first; falls back to text extraction
        for providers/models that do not support that parameter.
        """
        messages = [
            {
                "role": "system",
                "content": (
                    system_prompt
                    + "\n\nCRITICAL: Your entire response must be a single valid JSON object. "
                      "Do not include any text outside the JSON."
                ),
            },
            {"role": "user", "content": user_prompt},
        ]

        # --- Attempt 1: with json_object response format ---
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=4096,
            )
            raw = response.choices[0].message.content
            return _extract_json_from_text(raw)

        except Exception as primary_err:
            # Some models/providers reject response_format — retry without it
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.1,
                    max_tokens=4096,
                )
                raw = response.choices[0].message.content
                return _extract_json_from_text(raw)

            except Exception as fallback_err:
                return {
                    "error": f"LLM API failed. Primary: {primary_err}. Fallback: {fallback_err}"
                }
