import re
from decimal import Decimal
from typing import Optional, List, Any
from src.tools.contract_intel.backend.schemas import Terms, CostLine

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

def format_currency(amount: Optional[Decimal], currency_symbol: str = "₹") -> str:
    if amount is None:
        return "N/A"
    int_amt = int(amount)
    s = f"{int_amt}"
    if len(s) <= 3:
        return f"{currency_symbol}{s}"
    last_three = s[-3:]
    other = s[:-3]
    parts = []
    while len(other) > 0:
        parts.insert(0, other[-2:])
        other = other[:-2]
    return f"{currency_symbol}{','.join(parts)},{last_three}"

def calc_cost_model(terms: Terms) -> List[CostLine]:
    lines: List[CostLine] = []
    
    currency_term = terms.currency
    curr_symbol = "₹"
    if currency_term and currency_term.value:
        c_str = str(currency_term.value).upper()
        if "USD" in c_str or "$" in c_str:
            curr_symbol = "$"
        elif "EUR" in c_str or "€" in c_str:
            curr_symbol = "€"
        elif "GBP" in c_str or "£" in c_str:
            curr_symbol = "£"
            
    monthly = terms.monthly_price.value if terms.monthly_price else None
    term_months = terms.term_months.value if terms.term_months else None
    setup = terms.setup_fee.value if terms.setup_fee else None
    
    # 1. Initial Term Cost
    if monthly is not None and term_months is not None:
        m_dec = clean_decimal(monthly)
        t_dec = clean_decimal(term_months)
        s_dec = clean_decimal(setup)
        initial = (m_dec * t_dec) + s_dec
        sources = []
        if terms.monthly_price and terms.monthly_price.evidence:
            sources.append(f"p{terms.monthly_price.evidence.page}")
        if terms.term_months and terms.term_months.evidence:
            sources.append(f"p{terms.term_months.evidence.page}")
        if terms.setup_fee and terms.setup_fee.evidence:
            sources.append(f"p{terms.setup_fee.evidence.page}")
            
        lines.append(CostLine(
            label="Total Minimum Commitment (Initial Term)",
            amount=float(initial),
            formatted_amount=format_currency(initial, curr_symbol),
            formula_string=f"({curr_symbol}{m_dec} × {t_dec} months) + {curr_symbol}{s_dec} setup fee",
            sources=sources
        ))
    else:
        lines.append(CostLine(
            label="Total Minimum Commitment (Initial Term)",
            formula_string="monthly_price × term_months + setup_fee",
            sources=[],
            missing_reason="Missing monthly price or minimum term duration in contract text"
        ))

    # 2. Renewal Price Escalation Impact
    if terms.auto_renews and (terms.auto_renews.value is True or str(terms.auto_renews.value).lower() in ("true", "yes")):
        renewal_price = terms.renewal_price_monthly.value if terms.renewal_price_monthly else None
        if renewal_price is not None and monthly is not None:
            r_dec = clean_decimal(renewal_price)
            m_dec = clean_decimal(monthly)
            extra_annual = (r_dec - m_dec) * Decimal('12')
            sources = []
            if terms.renewal_price_monthly and terms.renewal_price_monthly.evidence:
                sources.append(f"p{terms.renewal_price_monthly.evidence.page}")
            if terms.monthly_price and terms.monthly_price.evidence:
                sources.append(f"p{terms.monthly_price.evidence.page}")
                
            lines.append(CostLine(
                label="Automatic Renewal Annual Escalation Impact",
                amount=float(extra_annual),
                formatted_amount=format_currency(extra_annual, curr_symbol),
                formula_string=f"({curr_symbol}{r_dec} renewed - {curr_symbol}{m_dec} initial) × 12 months",
                sources=sources
            ))
            
    # 3. Setup Fee / Non-refundable charges
    if setup is not None:
        s_dec = clean_decimal(setup)
        if s_dec > 0:
            sources = [f"p{terms.setup_fee.evidence.page}"] if terms.setup_fee and terms.setup_fee.evidence else []
            lines.append(CostLine(
                label="One-Time Onboarding / Setup Surcharge",
                amount=float(s_dec),
                formatted_amount=format_currency(s_dec, curr_symbol),
                formula_string="One-time non-refundable setup assessment",
                sources=sources
            ))
            
    return lines
