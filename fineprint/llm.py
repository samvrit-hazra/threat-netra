import json
from typing import Protocol, Type, Any, Dict
from pydantic import BaseModel
from groq import Groq
from fineprint.config import GROQ_API_KEY, GROQ_MODEL, console

class LLMClient(Protocol):
    def generate_json(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        ...

class GroqClient:
    def __init__(self):
        self.client = Groq(api_key=GROQ_API_KEY)
        self.model = GROQ_MODEL

    def check_connection(self):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Return a JSON object with a single key 'status' and value 'ok'."}],
                response_format={"type": "json_object"}
            )
            return True, [self.model], response.choices[0].message.content
        except Exception as e:
            return False, [], str(e)

    def generate_json(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        schema_json = schema_model.model_json_schema()
        full_prompt = f"{prompt}\n\nOutput strictly as a JSON object matching this schema:\n{json.dumps(schema_json, indent=2)}\n"
        
        max_retries = 5
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                import time
                import random
                time.sleep(1) # Minimum delay
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": full_prompt}],
                    response_format={"type": "json_object"}
                )
                
                text = response.choices[0].message.content.strip()
                
                data = json.loads(text.strip())
                validated = schema_model(**data)
                return validated.model_dump()
                
            except Exception as e:
                import time
                import random
                if attempt == max_retries - 1:
                    console.print(f"[bold red]API/Validation failed after {max_retries} attempts: {e}[/bold red]")
                    raise
                
                if "validation" in str(type(e)).lower() or "jsondecodeerror" in str(type(e)).lower():
                    full_prompt += f"\nYour previous output failed: {e}\nPlease correct it and output ONLY valid JSON."
                else:
                    err_str = str(e).lower()
                    
                    if "insufficient" in err_str or "credits" in err_str or "billing" in err_str or "quota" in err_str:
                        console.print(f"\n[bold red]Groq API Error: You have run out of API credits or exceeded your hard quota![/bold red]")
                        console.print(f"[dim]{e}[/dim]")
                        raise
                        
                    if "429" in err_str or "rate limit" in err_str or "413" in err_str:
                        delay = (base_delay ** attempt) * 5 + random.uniform(5, 10)
                        console.print(f"[yellow]Groq API rate limit hit (too many requests/minute). Pausing for {delay:.1f}s...[/yellow]")
                    else:
                        delay = (base_delay ** attempt) + random.uniform(0, 1)
                        console.print(f"[yellow]API error, retrying in {delay:.1f}s... (Error: {type(e).__name__})[/yellow]")
                    time.sleep(delay)
                    
        return {}

class FakeLLM:
    def __init__(self, canned_responses=None):
        self.canned_responses = canned_responses or []
        self.call_count = 0
        
    def generate_json(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        response = self.canned_responses[self.call_count] if self.call_count < len(self.canned_responses) else {}
        self.call_count += 1
        return response
