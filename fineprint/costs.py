from decimal import Decimal
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fineprint.schemas import Terms

class CostLine(BaseModel):
    label: str
    amount: Optional[Decimal] = None
    formula_string: str
    sources: List[str]
    missing_reason: Optional[str] = None

import re

def clean_decimal(val: Any) -> Decimal:
    if val is None:
        return Decimal('0')
    if isinstance(val, (int, float, Decimal)):
        return Decimal(str(val))
    s = str(val).replace(',', '')
    match = re.search(r'\d+(?:\.\d+)?', s)
    if match:
        return Decimal(match.group())
    return Decimal('0')

def format_inr(amount: Decimal) -> str:
    if amount is None: return "N/A"
    s = f"{int(amount)}"
    if len(s) <= 3: return f"₹{s}"
    last_three = s[-3:]
    other = s[:-3]
    parts = []
    while len(other) > 0:
        parts.insert(0, other[-2:])
        other = other[:-2]
    return f"₹{','.join(parts)},{last_three}"

def calc_costs(terms: Terms, cancel_after_month: Optional[int] = None) -> List[CostLine]:
    lines = []
    
    monthly = terms.monthly_price.value if terms.monthly_price else None
    term_months = terms.term_months.value if terms.term_months else None
    setup = terms.setup_fee.value if terms.setup_fee else None
    
    # 1. Initial term cost
    if monthly is not None and term_months is not None:
        initial = clean_decimal(monthly) * clean_decimal(term_months) + clean_decimal(setup)
        sources = []
        if terms.monthly_price: sources.append(f"p{terms.monthly_price.evidence.page}")
        if terms.term_months: sources.append(f"p{terms.term_months.evidence.page}")
        if terms.setup_fee: sources.append(f"p{terms.setup_fee.evidence.page}")
        lines.append(CostLine(label="Initial Term Cost", amount=initial, formula_string=f"monthly_price × term_months + setup_fee", sources=sources))
    else:
        lines.append(CostLine(label="Initial Term Cost", formula_string="monthly_price × term_months + setup_fee", sources=[], missing_reason="Missing monthly price or term length"))

    # 2. Renewal Extra Annual
    if terms.auto_renews and terms.auto_renews.value is True:
        renewal_price = terms.renewal_price_monthly.value if terms.renewal_price_monthly else None
        if renewal_price is not None and monthly is not None:
            extra = (clean_decimal(renewal_price) - clean_decimal(monthly)) * Decimal('12')
            s2 = [f"p{terms.renewal_price_monthly.evidence.page}", f"p{terms.monthly_price.evidence.page}"]
            lines.append(CostLine(label="Renewal Impact (Annual Extra)", amount=extra, formula_string="(renewal_price - monthly_price) × 12", sources=s2))
            
    return lines
