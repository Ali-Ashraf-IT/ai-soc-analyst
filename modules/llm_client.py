import os
import json
from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class LLMClient:
    def __init__(self, api_key=None, base_url=None, model=None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
        self.model = model or os.getenv("LLM_MODEL", "llama-3.1-70b-versatile")
        
        if not self.api_key:
            raise ValueError("LLM_API_KEY is not set. Please configure it in .env or the Streamlit sidebar.")
            
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )

    def generate_json(self, system_prompt: str, user_prompt: str, schema_class: type[BaseModel] = None):
        """
        Calls the LLM and requests a JSON response. 
        If schema_class is provided, it tries to validate the response.
        """
        messages = [
            {"role": "system", "content": system_prompt + "\n\nYou must respond in valid JSON format."},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            # We use standard chat completion with json_object format
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            result_str = response.choices[0].message.content
            
            # Parse the JSON
            try:
                parsed_json = json.loads(result_str)
                if schema_class:
                    # Validate against pydantic schema
                    validated = schema_class(**parsed_json)
                    return validated.model_dump()
                return parsed_json
            except json.JSONDecodeError:
                return {"error": "LLM did not return valid JSON", "raw_output": result_str}
            except Exception as e:
                return {"error": f"Schema validation failed: {str(e)}", "raw_output": result_str}
                
        except Exception as e:
            return {"error": f"LLM API request failed: {str(e)}"}
