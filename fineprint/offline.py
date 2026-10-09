import json
import os
from fineprint.schemas import FindingsOutput, Terms

def load_precomputed_results(pdf_path: str, is_terms: bool = False):
    base = os.path.basename(pdf_path).replace(".pdf", "")
    suffix = "terms" if is_terms else "findings"
    path = f"samples/precomputed/{base}_{suffix}.json"
    
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

class OfflineLLM:
    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        
    def generate_json(self, prompt: str, schema_model) -> dict:
        is_terms = "monthly_price" in json.dumps(schema_model.model_json_schema())
        return load_precomputed_results(self.pdf_path, is_terms)
