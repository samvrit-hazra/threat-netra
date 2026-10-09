from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from enum import Enum
from decimal import Decimal

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
    early_termination_fee: Optional[Term] = None
    refund_policy_summary: Optional[Term] = None
    price_change_clause: Optional[Term] = None

class CostLine(BaseModel):
    label: str
    amount: Optional[float] = None
    formatted_amount: Optional[str] = None
    formula_string: str
    sources: List[str] = []
    missing_reason: Optional[str] = None

class FindingsOutput(BaseModel):
    findings: List[Finding]

class AnalysisResult(BaseModel):
    document_meta: Dict[str, Any]
    findings: List[Finding]
    terms: Terms
    cost_model: List[CostLine] = []
    discarded_findings: List[Finding] = []
    warnings: List[str] = []

class AskRequest(BaseModel):
    question: str
    raw_text: Optional[str] = None
    sha256: Optional[str] = None

class Citation(BaseModel):
    page: int
    quote: str
    verified: bool = False

class AskResponse(BaseModel):
    answerable: bool
    answer: str
    citations: List[Citation] = []

class CompareRequest(BaseModel):
    text_a: str
    text_b: str
    name_a: Optional[str] = "Contract A"
    name_b: Optional[str] = "Contract B"

class CompareRow(BaseModel):
    label: str
    a_val: str
    b_val: str
    a_ev: str = ""
    b_ev: str = ""
    diff: bool = False

class CompareResult(BaseModel):
    name_a: str
    name_b: str
    comparison_table: List[CompareRow]
    verdict: str
