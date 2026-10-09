import re
from typing import Set
from rapidfuzz import fuzz
from src.tools.contract_intel.backend.schemas import Finding, Term, AnalysisResult, Document
from src.tools.contract_intel.backend.extractor import normalize_text_with_map

def clean_numbers(s: str) -> Set[float]:
    nums = re.findall(r'\d+(?:\.\d+)?', s.replace(',', ''))
    return {float(n) for n in nums}

def validate_finding(finding: Finding, doc: Document) -> Finding:
    if finding.page < 1 or finding.page > len(doc.pages):
        finding.verified = False
        finding.match_method = "none"
        # Try checking all pages before giving up
        for i, page in enumerate(doc.pages):
            p_norm, _ = normalize_text_with_map(page.text)
            source_norm, _ = normalize_text_with_map(finding.source_text)
            if source_norm in p_norm:
                finding.verified = True
                finding.match_method = "page_corrected"
                finding.verified_page = i + 1
                return finding
        return finding
        
    source_norm, _ = normalize_text_with_map(finding.source_text)
    
    # 1. Exact/Normalized match on the stated page
    page_text = doc.pages[finding.page - 1].text
    page_norm, _ = normalize_text_with_map(page_text)
    
    if source_norm in page_norm:
        finding.verified = True
        finding.match_method = "exact" if finding.source_text in page_text else "normalized"
        finding.verified_page = finding.page
        return finding
        
    # 2. Check other pages
    for i, page in enumerate(doc.pages):
        if i + 1 == finding.page:
            continue
        p_norm, _ = normalize_text_with_map(page.text)
        if source_norm in p_norm:
            finding.verified = True
            finding.match_method = "page_corrected"
            finding.verified_page = i + 1
            return finding
            
    # 3. Fuzzy search across all pages
    best_ratio = 0
    best_page = None
    
    for i, page in enumerate(doc.pages):
        p_norm, _ = normalize_text_with_map(page.text)
        ratio = fuzz.partial_ratio(source_norm, p_norm)
        if ratio > best_ratio:
            best_ratio = ratio
            best_page = i + 1
            
    if best_ratio >= 85:
        finding.verified = True
        finding.match_method = "fuzzy"
        finding.verified_page = best_page
        return finding
            
    finding.verified = False
    finding.match_method = "none"
    return finding

def validate_term(term: Term, doc: Document) -> bool:
    if not term.evidence or not term.evidence.source_text:
        return False
        
    f = Finding(
        id="T1", category="fees", severity="info", title="term", 
        page=term.evidence.page, source_text=term.evidence.source_text,
        explanation="", potential_consequence=""
    )
    validated = validate_finding(f, doc)
    
    if not validated.verified:
        return False
        
    term.evidence.page = validated.verified_page or term.evidence.page
    
    # Numeric check
    val_str = str(term.value)
    if not isinstance(term.value, bool) and any(c.isdigit() for c in val_str):
        val_nums = clean_numbers(val_str)
        source_nums = clean_numbers(term.evidence.source_text)
        for num in val_nums:
            if num not in source_nums:
                return False
                
    return True

def validate_analysis(result: AnalysisResult, doc: Document) -> AnalysisResult:
    valid_findings = []
    discarded = []
    
    for f in result.findings:
        validated = validate_finding(f, doc)
        if validated.verified:
            valid_findings.append(validated)
        else:
            discarded.append(validated)
            
    result.findings = valid_findings
    result.discarded_findings = discarded
    
    # Validate terms
    terms_dict = result.terms.model_dump()
    for field_name, term_obj in terms_dict.items():
        if term_obj is not None:
            t = Term(**term_obj)
            if not validate_term(t, doc):
                setattr(result.terms, field_name, None)
                
    return result
