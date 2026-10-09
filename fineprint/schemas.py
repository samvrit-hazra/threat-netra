from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from enum import Enum

class Page(BaseModel):
    number: int
    text: str

class Document(BaseModel):
    path: str
    sha256: str
    pages: List[Page]

class Category(str, Enum):
    fees = "fees"
    automatic_renewal = "automatic_renewal"
    cancellation = "cancellation"
    early_termination = "early_termination"
    refunds = "refunds"
    deposits = "deposits"
    price_changes = "price_changes"
    payment_obligations = "payment_obligations"
    liability = "liability"
    privacy_data_use = "privacy_data_use"
    service_limitations = "service_limitations"
    penalties = "penalties"
    notice_requirements = "notice_requirements"
    deadlines = "deadlines"

class Severity(str, Enum):
    high = "high"
    medium = "medium"
    info = "info"

class Finding(BaseModel):
    id: str
    category: Category
    severity: Severity
    title: str
    page: int
    clause_ref: Optional[str] = None
    source_text: str
    explanation: str
    potential_consequence: str
    missing_information: List[str] = []
    
    verified: bool = False
    match_method: str = "none"
    verified_page: Optional[int] = None

class Evidence(BaseModel):
    page: int
    clause_ref: Optional[str] = None
    source_text: str

class Term(BaseModel):
    value: Any
    evidence: Evidence

class Terms(BaseModel):
    currency: Optional[Term] = None
    monthly_price: Optional[Term] = None
    term_months: Optional[Term] = None
    setup_fee: Optional[Term] = None
    deposit: Optional[Term] = None
    auto_renews: Optional[Term] = None
    renewal_price_monthly: Optional[Term] = None
    renewal_term_months: Optional[Term] = None
    cancellation_notice_days: Optional[Term] = None
    early_termination_fee: Optional[Term] = None # object with type, amount, percent
    refund_policy_summary: Optional[Term] = None
    price_change_clause: Optional[Term] = None

class FindingsOutput(BaseModel):
    findings: List[Finding]

class AnalysisResult(BaseModel):
    document_meta: Dict[str, Any]
    findings: List[Finding]
    terms: Terms
    discarded_findings: List[Finding] = []
    warnings: List[str] = []
