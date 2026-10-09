from typing import Dict, Any, List
from pydantic import BaseModel
from fineprint.schemas import Terms
from fineprint.llm import LLMClient

def compare_terms(terms_a: Terms, terms_b: Terms) -> List[Dict[str, Any]]:
    rows = []
    fields = [
        ("Monthly Price", "monthly_price"),
        ("Term (Months)", "term_months"),
        ("Setup Fee", "setup_fee"),
        ("Auto Renews", "auto_renews"),
        ("Renewal Price", "renewal_price_monthly"),
        ("Cancellation Notice", "cancellation_notice_days"),
    ]
    
    for label, field in fields:
        a_val = getattr(terms_a, field)
        b_val = getattr(terms_b, field)
        
        a_v = a_val.value if a_val else "Not specified"
        b_v = b_val.value if b_val else "Not specified"
        
        diff = a_v != b_v
        
        rows.append({
            "label": label,
            "A_val": a_v,
            "B_val": b_v,
            "A_ev": f"p{a_val.evidence.page}" if a_val and a_val.evidence else "",
            "B_ev": f"p{b_val.evidence.page}" if b_val and b_val.evidence else "",
            "diff": diff
        })
        
    return rows

class VerdictResponse(BaseModel):
    verdict: str

def generate_verdict(rows: List[Dict[str, Any]], llm: LLMClient) -> str:
    prompt = "Compare these stated terms and provide a short, neutral verdict mentioning trade-offs. Give no legal recommendation.\n\n"
    for r in rows:
        prompt += f"{r['label']}: A={r['A_val']}, B={r['B_val']}\n"
        
    try:
        resp = llm.generate_json(prompt, VerdictResponse)
        return resp.get("verdict", "Comparison: The contracts have different terms. Please review carefully.")
    except Exception:
        return "Comparison: The contracts have different terms. Please review carefully."
