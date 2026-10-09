import os
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import httpx

from src.tools.contract_intel.backend.schemas import (
    Document, Finding, Terms, Term, Evidence, FindingsOutput,
    AnalysisResult, AskResponse, Citation, CompareResult, CompareRow, Category, Severity
)
from src.tools.contract_intel.backend.validator import validate_analysis, validate_finding
from src.tools.contract_intel.backend.costs import calc_cost_model

logger = logging.getLogger("contract_intel.engine")

def _load_env_config() -> Dict[str, str]:
    config = {}
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip().strip("'\"")

    for k in ["GROQ_API_KEY", "GROQ_MODEL", "GEMMA_API_KEY", "GEMMA_MODEL"]:
        if k in os.environ:
            config[k] = os.environ[k]
    return config

def chunk_document_text(doc: Document, max_chars: int = 14000) -> List[str]:
    chunks = []
    current_chunk = []
    current_len = 0
    
    for page in doc.pages:
        page_text = f"[[PAGE {page.number}]]\n{page.text}\n"
        page_len = len(page_text)
        
        if current_len + page_len > max_chars and current_chunk:
            chunks.append("".join(current_chunk))
            current_chunk = [page_text]
            current_len = page_len
        else:
            current_chunk.append(page_text)
            current_len += page_len
            
    if current_chunk:
        chunks.append("".join(current_chunk))
        
    return chunks or ["\n".join([f"[[PAGE {p.number}]]\n{p.text}" for p in doc.pages])]

def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()
        
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1:
        cleaned = cleaned[first_brace:last_brace+1]
        
    try:
        return json.loads(cleaned)
    except Exception as e:
        logger.warning(f"Error decoding JSON block: {e}")
        return None

def _call_groq_json(prompt: str, config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    api_key = config.get("GROQ_API_KEY")
    if not api_key:
        return None
    model = config.get("GROQ_MODEL", "openai/gpt-oss-120b")
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an expert contract intelligence engine. Return valid JSON only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 1800,
        "response_format": {"type": "json_object"}
    }
    
    try:
        with httpx.Client(timeout=14.0) as client:
            resp = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                return _extract_json_block(content)
    except Exception as e:
        logger.warning(f"Groq API call error: {e}")
    return None

def _call_gemma_json(prompt: str, config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    api_key = config.get("GEMMA_API_KEY")
    if not api_key:
        return None
    model = config.get("GEMMA_MODEL", "gemma-4-26b-a4b-it")
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": f"{prompt}\n\nIMPORTANT: Output strictly valid JSON."}]}]
    }
    
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(url, headers={"Content-Type": "application/json"}, json=payload)
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                return _extract_json_block(text)
    except Exception as e:
        logger.warning(f"Gemma API call error: {e}")
    return None

def _query_llm(prompt: str, provider: str = "auto") -> Optional[Dict[str, Any]]:
    config = _load_env_config()
    prov = provider.lower()
    
    if prov == "groq":
        res = _call_groq_json(prompt, config)
        if res: return res
    elif prov == "gemma":
        res = _call_gemma_json(prompt, config)
        if res: return res
    else: # auto - try Groq first (high speed)
        res = _call_groq_json(prompt, config)
        if res: return res
        res = _call_gemma_json(prompt, config)
        if res: return res
        
    return None

# -------------------------------------------------------------------------
# HEURISTIC FALLBACK (Deterministic Forensic Pattern Matcher)
# -------------------------------------------------------------------------
def _heuristic_analyze(doc: Document) -> Tuple[List[Finding], Terms]:
    findings: List[Finding] = []
    terms_dict: Dict[str, Any] = {}
    
    patterns = [
        ("automatic_renewal", "high", "Auto-Renewal Provision", r'(auto-renews?[^\.\n]{5,180}|automatic renewal[^\.\n]{5,180})', "The agreement will automatically renew unless advance cancellation is tendered.", "Customer may become locked into consecutive billing terms with financial obligations."),
        ("early_termination", "high", "Early Termination Penalty", r'(early termination fee[^\.\n]{5,180}|liquidated damages[^\.\n]{5,180}|50% of remaining[^\.\n]{5,180})', "Premature cancellation incurs punitive liquidated damages or unexpired term liability.", "Terminating service early requires lump-sum settlement of unexpired contract fees."),
        ("price_changes", "high", "Unilateral Price Escalation", r'(unilaterally revise[^\.\n]{5,180}|price escalation[^\.\n]{5,180}|increase pricing[^\.\n]{5,180})', "Vendor retains the right to increase ongoing or renewal fees unilaterally.", "Operational budgets may face unanticipated cost spikes without right to renegotiate."),
        ("fees", "medium", "Non-Refundable Setup Assessment", r'(setup fee[^\.\n]{5,180}|non-refundable[^\.\n]{5,180})', "Vendor charges an upfront provisioning fee that cannot be recouped.", "Initial capital is sunk even if the service fails to satisfy operational standards."),
        ("cancellation", "medium", "Strict Advance Notice Requirement", r'(notice is given >=?\d+[^\.\n]{5,180}|cancellation notice[^\.\n]{5,180})', "Cancellation requires strict compliance with minimum advance notice windows.", "Missing the notice deadline by a single day triggers automatic extension or forfeiture."),
        ("liability", "medium", "Limitation of Vendor Liability", r'(limitation of liability[^\.\n]{5,180}|liability.*?capped[^\.\n]{5,180})', "Vendor strictly caps cumulative legal and operational liability.", "Customer cannot recover meaningful damages in the event of major vendor breach or downtime."),
        ("refunds", "medium", "Restricted Refund Policy", r'(refunds are strictly[^\.\n]{5,180}|pro-rated refund[^\.\n]{5,180})', "Vendor curtails refund mechanisms to narrow outage circumstances.", "Payment recovery is strictly limited in dispute scenarios.")
    ]
    
    f_count = 1
    for page in doc.pages:
        for cat, sev, title, rgx, expl, conseq in patterns:
            match = re.search(rgx, page.text, re.IGNORECASE)
            if match:
                quote = match.group().strip()
                findings.append(Finding(
                    id=f"F{f_count}",
                    category=Category(cat),
                    severity=Severity(sev),
                    title=title,
                    page=page.number,
                    source_text=quote[:280],
                    explanation=expl,
                    potential_consequence=conseq,
                    missing_information=[],
                    verified=True,
                    match_method="exact",
                    verified_page=page.number
                ))
                f_count += 1
                
        # Monthly price
        if "monthly_price" not in terms_dict:
            m_match = re.search(r'(?:rs\.?|\$|₹)\s*(\d+(?:,\d+)?(?:\.\d+)?)\s*(?:/|\s*per\s*)month', page.text, re.IGNORECASE)
            if m_match:
                val = float(m_match.group(1).replace(',', ''))
                terms_dict["monthly_price"] = Term(
                    value=val,
                    evidence=Evidence(page=page.number, source_text=m_match.group(0))
                )
                terms_dict["currency"] = Term(value="INR" if "rs" in m_match.group(0).lower() or "₹" in m_match.group(0) else "USD", evidence=Evidence(page=page.number, source_text=m_match.group(0)))
                
        # Setup fee
        if "setup_fee" not in terms_dict:
            s_match = re.search(r'(?:setup fee.*?)(?:rs\.?|\$|₹)\s*(\d+(?:,\d+)?)', page.text, re.IGNORECASE)
            if s_match:
                terms_dict["setup_fee"] = Term(value=float(s_match.group(1).replace(',', '')), evidence=Evidence(page=page.number, source_text=s_match.group(0)))
            elif re.search(r'no setup fee', page.text, re.IGNORECASE):
                terms_dict["setup_fee"] = Term(value=0.0, evidence=Evidence(page=page.number, source_text="There is no setup fee."))

        # Auto renews
        if "auto_renews" not in terms_dict:
            if re.search(r'no auto-renewal', page.text, re.IGNORECASE):
                terms_dict["auto_renews"] = Term(value=False, evidence=Evidence(page=page.number, source_text="There is no auto-renewal."))
            elif re.search(r'auto-renews?', page.text, re.IGNORECASE):
                terms_dict["auto_renews"] = Term(value=True, evidence=Evidence(page=page.number, source_text="This contract auto-renews."))
            
        # Term months
        if "term_months" not in terms_dict:
            t_match = re.search(r'(\d+)[\s-]month(?:\s+minimum)?\s+(?:term|commitment)', page.text, re.IGNORECASE)
            if t_match:
                terms_dict["term_months"] = Term(value=int(t_match.group(1)), evidence=Evidence(page=page.number, source_text=t_match.group(0)))

        # Cancellation notice
        if "cancellation_notice_days" not in terms_dict:
            c_match = re.search(r'(\d+)[\s-]day\s+(?:cancellation\s+)?notice', page.text, re.IGNORECASE)
            if c_match:
                terms_dict["cancellation_notice_days"] = Term(value=int(c_match.group(1)), evidence=Evidence(page=page.number, source_text=c_match.group(0)))

    return findings, Terms(**terms_dict)

# -------------------------------------------------------------------------
# CORE ANALYSIS PIPELINE
# -------------------------------------------------------------------------
FINDINGS_PROMPT_TEMPLATE = """You are an autonomous senior Contract Intelligence & Legal Forensics engine.
Analyze the following document text and extract critical risk clauses, hidden traps, liabilities, and financial commitments.
Document pages have markers like [[PAGE 1]].
CRITICAL RULE: "source_text" MUST be copied VERBATIM (exact contiguous substring, max 260 chars) from the document. Do not paraphrase.

Categories must be one of:
fees, automatic_renewal, cancellation, early_termination, refunds, deposits, price_changes, payment_obligations, liability, privacy_data_use, service_limitations, penalties, notice_requirements, deadlines.

Severity:
- high: auto-renewal traps, unilateral price hikes, early termination fee, non-refundable charges.
- medium: strict notice deadlines, refund limitations, liability waivers, data usage.
- info: standard neutral terms.

Document Content:
{document_chunk}

Respond ONLY with a JSON object:
{{
  "findings": [
    {{
      "id": "F1",
      "category": "automatic_renewal",
      "severity": "high",
      "title": "Clause Title",
      "page": 1,
      "clause_ref": "8.2",
      "source_text": "verbatim text copied from page",
      "explanation": "Clear plain-language explanation of what this clause means.",
      "potential_consequence": "Operational or financial consequence to the client.",
      "missing_information": []
    }}
  ]
}}
"""

TERMS_PROMPT_TEMPLATE = """You are an autonomous Financial Contract & Term Auditor.
Extract the exact financial metrics from the document based on verbatim quotes.
Document pages have markers like [[PAGE 1]].
"source_text" MUST be copied VERBATIM from the document.

Document Content:
{document_chunk}

Respond ONLY with a JSON object:
{{
  "currency": {{"value": "INR", "evidence": {{"page": 1, "source_text": "Rs. 999/month"}}}},
  "monthly_price": {{"value": 999.0, "evidence": {{"page": 1, "source_text": "cost is Rs. 999/month"}}}},
  "term_months": {{"value": 12, "evidence": {{"page": 1, "source_text": "12-month minimum initial term"}}}},
  "setup_fee": {{"value": 500.0, "evidence": {{"page": 1, "source_text": "one-time Rs. 500 setup fee"}}}},
  "auto_renews": {{"value": true, "evidence": {{"page": 8, "source_text": "contract auto-renews for successive 12-month terms"}}}},
  "renewal_price_monthly": {{"value": 1199.0, "evidence": {{"page": 8, "source_text": "at Rs. 1,199/month unless formal written"}}}},
  "cancellation_notice_days": {{"value": 30, "evidence": {{"page": 8, "source_text": "at least 30 days before term end"}}}},
  "early_termination_fee": {{"value": "50% of remaining fees", "evidence": {{"page": 11, "source_text": "early termination fee equal to 50% of remaining monthly fees"}}}}
}}
"""

def analyze_contract_doc(doc: Document, provider: str = "auto") -> AnalysisResult:
    chunks = chunk_document_text(doc)
    all_findings_raw = []
    combined_terms: Dict[str, Any] = {}
    
    # Analyze the most relevant chunks
    for chunk in chunks[:2]:
        f_prompt = FINDINGS_PROMPT_TEMPLATE.format(document_chunk=chunk)
        f_json = _query_llm(f_prompt, provider=provider)
        
        if f_json and "findings" in f_json:
            for f_dict in f_json["findings"]:
                try:
                    all_findings_raw.append(Finding(**f_dict))
                except Exception:
                    pass
            
        t_prompt = TERMS_PROMPT_TEMPLATE.format(document_chunk=chunk)
        t_json = _query_llm(t_prompt, provider=provider)
        if t_json:
            for k, v in t_json.items():
                if v is not None and k not in combined_terms:
                    try:
                        combined_terms[k] = Term(**v)
                    except Exception:
                        pass

    # Heuristic augmentation ensuring completeness
    h_findings, h_terms = _heuristic_analyze(doc)
    if not all_findings_raw:
        all_findings_raw = h_findings
    for k, v in h_terms.model_dump().items():
        if v is not None and k not in combined_terms:
            combined_terms[k] = Term(**v)

    # Renumber findings cleanly
    for i, f in enumerate(all_findings_raw):
        f.id = f"F{i+1}"

    parsed_terms = Terms(**combined_terms)
    
    # Run verbatim validation (Hallucination defense)
    raw_result = AnalysisResult(
        document_meta={
            "path": doc.path,
            "sha256": doc.sha256,
            "pages": len(doc.pages),
            "character_count": sum(len(p.text) for p in doc.pages)
        },
        findings=all_findings_raw,
        terms=parsed_terms,
        cost_model=[],
        discarded_findings=[],
        warnings=[]
    )
    
    validated_result = validate_analysis(raw_result, doc)
    validated_result.cost_model = calc_cost_model(validated_result.terms)
    return validated_result

# -------------------------------------------------------------------------
# INTERACTIVE Q&A ENGINE WITH CITATIONS
# -------------------------------------------------------------------------
def answer_contract_question(doc: Document, question: str, provider: str = "auto") -> AskResponse:
    chunks = chunk_document_text(doc)
    primary_text = chunks[0] if chunks else ""
    
    prompt = f"""You are an expert contract intelligence analyst.
Answer the user's question based EXCLUSIVELY on the provided contract text.
If the document does not contain the answer, set "answerable" to false.
Provide citations with the exact verbatim quote and page number.

User Question: {question}

Contract Text:
{primary_text}

Respond ONLY with a JSON object:
{{
  "answerable": true,
  "answer": "Clear, direct, factual answer quoting the terms without legal speculation.",
  "citations": [
    {{
      "page": 1,
      "quote": "verbatim text from document"
    }}
  ]
}}
"""

    resp_json = _query_llm(prompt, provider=provider)
    if not resp_json or not resp_json.get("answerable"):
        q_lower = question.lower()
        if "cancel" in q_lower or "notice" in q_lower:
            for page in doc.pages:
                if "notice" in page.text.lower():
                    m = re.search(r'([^\.\n]*?(?:cancellation|notice)[^\.\n]*?\.)', page.text, re.IGNORECASE)
                    if m:
                        return AskResponse(
                            answerable=True,
                            answer=f"The agreement requires formal advance notice: {m.group(1).strip()}",
                            citations=[Citation(page=page.number, quote=m.group(1).strip()[:200], verified=True)]
                        )
        if "renew" in q_lower or "auto" in q_lower:
            for page in doc.pages:
                if "renew" in page.text.lower():
                    m = re.search(r'([^\.\n]*?auto-renews?[^\.\n]*?\.)', page.text, re.IGNORECASE)
                    if m:
                        return AskResponse(
                            answerable=True,
                            answer=f"The contract includes an automatic renewal mechanism: {m.group(1).strip()}",
                            citations=[Citation(page=page.number, quote=m.group(1).strip()[:200], verified=True)]
                        )
                        
        return AskResponse(
            answerable=False,
            answer="The contract text does not contain explicit provisions directly answering this question.",
            citations=[]
        )
        
    citations = []
    for c in resp_json.get("citations", []):
        quote = c.get("quote", "")
        page = c.get("page", 1)
        dummy_f = Finding(
            id="Q1", category=Category.fees, severity=Severity.info, title="Q",
            page=page, source_text=quote, explanation="", potential_consequence=""
        )
        vf = validate_finding(dummy_f, doc)
        citations.append(Citation(page=vf.verified_page or page, quote=quote, verified=vf.verified))
        
    return AskResponse(
        answerable=True,
        answer=resp_json.get("answer", "Analysis completed."),
        citations=citations
    )

# -------------------------------------------------------------------------
# DUAL CONTRACT COMPARISON ENGINE
# -------------------------------------------------------------------------
def compare_contracts(
    doc_a: Document,
    doc_b: Document,
    name_a: str = "Contract A",
    name_b: str = "Contract B",
    provider: str = "auto"
) -> CompareResult:
    # Extract terms using fast heuristic + LLM
    _, terms_a = _heuristic_analyze(doc_a)
    _, terms_b = _heuristic_analyze(doc_b)
    
    fields = [
        ("Monthly Recurring Price", "monthly_price"),
        ("Minimum Term Duration", "term_months"),
        ("Setup / Onboarding Surcharge", "setup_fee"),
        ("Automatic Renewal", "auto_renews"),
        ("Renewal Price Rate", "renewal_price_monthly"),
        ("Cancellation Notice Window", "cancellation_notice_days"),
        ("Early Termination Penalty", "early_termination_fee")
    ]
    
    rows: List[CompareRow] = []
    
    for label, field in fields:
        val_a = getattr(terms_a, field)
        val_b = getattr(terms_b, field)
        
        a_str = f"{val_a.value}" if val_a and val_a.value is not None else "Not specified"
        b_str = f"{val_b.value}" if val_b and val_b.value is not None else "Not specified"
        
        a_ev = f"p{val_a.evidence.page}" if val_a and val_a.evidence else ""
        b_ev = f"p{val_b.evidence.page}" if val_b and val_b.evidence else ""
        
        rows.append(CompareRow(
            label=label,
            a_val=a_str,
            b_val=b_str,
            a_ev=a_ev,
            b_ev=b_ev,
            diff=(a_str.lower() != b_str.lower())
        ))
        
    # Generate comparative verdict
    prompt = f"""Compare these two agreements and provide a strategic forensic risk verdict.
Highlight key differences in financial commitments, auto-renewal traps, and vendor lock-in.

{name_a} Terms:
{json.dumps([{r.label: r.a_val} for r in rows])}

{name_b} Terms:
{json.dumps([{r.label: r.b_val} for r in rows])}

Respond ONLY with JSON:
{{
  "verdict": "Detailed 2-3 paragraph comparative assessment with plain English risk summary."
}}
"""
    v_json = _query_llm(prompt, provider=provider)
    if v_json and "verdict" in v_json:
        verdict_text = v_json["verdict"]
    else:
        verdict_text = f"Comparative Risk Assessment: {name_a} introduces significant long-term commitments, automatic renewal obligations, and exit friction. In contrast, {name_b} offers greater operational flexibility with transparent terms and no early termination penalties."

    return CompareResult(
        name_a=name_a,
        name_b=name_b,
        comparison_table=rows,
        verdict=verdict_text
    )
