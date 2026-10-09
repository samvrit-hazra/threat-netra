from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from fineprint.schemas import Document, Finding, Terms, FindingsOutput, AnalysisResult
from fineprint.prompts import FINDINGS_PROMPT, TERMS_PROMPT, PROMPT_VERSION
from fineprint.config import MAX_CHARS_PER_CALL, console
from fineprint.cache import get_cache_key, load_cache, save_cache
from fineprint.llm import LLMClient

def chunk_document(doc: Document, max_chars: int) -> List[str]:
    chunks = []
    current_chunk = []
    current_len = 0
    
    for page in doc.pages:
        page_text = f"[[PAGE {page.number}]]\n{page.text}\n"
        page_len = len(page_text)
        
        if current_len + page_len > max_chars and current_chunk:
            chunks.append("".join(current_chunk))
            current_chunk = [f"[[PAGE {page.number-1}]]\n{doc.pages[page.number-2].text}\n", page_text] if page.number > 1 else [page_text]
            current_len = sum(len(c) for c in current_chunk)
        else:
            current_chunk.append(page_text)
            current_len += page_len
            
    if current_chunk:
        chunks.append("".join(current_chunk))
        
    return chunks

def merge_findings(findings_lists: List[List[Dict]]) -> List[Finding]:
    merged = []
    seen = set()
    
    for findings in findings_lists:
        for f in findings:
            key = (f['category'], f['source_text'])
            if key not in seen:
                seen.add(key)
                merged.append(Finding(**f))
                
    for i, f in enumerate(merged):
        f.id = f"F{i+1}"
    return merged

def analyze_document(doc: Document, llm: LLMClient, use_cache: bool = True) -> AnalysisResult:
    chunks = chunk_document(doc, MAX_CHARS_PER_CALL)
    
    all_findings_raw = []
    terms_dict = {}
    
    for i, chunk in enumerate(chunks):
        # Findings
        key_f = get_cache_key(doc.sha256, getattr(llm, 'model', 'fake'), PROMPT_VERSION, "findings", i)
        cached_f = load_cache(key_f) if use_cache else None
        
        if cached_f:
            findings_data = cached_f
        else:
            prompt = f"{FINDINGS_PROMPT}\n\nDocument Text:\n{chunk}"
            findings_data = llm.generate_json(prompt, FindingsOutput)
            if use_cache: save_cache(key_f, findings_data)
                
        all_findings_raw.append(findings_data.get('findings', []))
        
        # Terms
        key_t = get_cache_key(doc.sha256, getattr(llm, 'model', 'fake'), PROMPT_VERSION, "terms", i)
        cached_t = load_cache(key_t) if use_cache else None
        
        if cached_t:
            terms_data = cached_t
        else:
            prompt = f"{TERMS_PROMPT}\n\nDocument Text:\n{chunk}"
            terms_data = llm.generate_json(prompt, Terms)
            if use_cache: save_cache(key_t, terms_data)
                
        for k, v in terms_data.items():
            if v is not None and terms_dict.get(k) is None:
                terms_dict[k] = v
                
    merged_findings = merge_findings(all_findings_raw)
    
    from fineprint.validate import validate_analysis
    
    result = AnalysisResult(
        document_meta={"path": doc.path, "sha256": doc.sha256, "pages": len(doc.pages)},
        findings=merged_findings,
        terms=Terms(**terms_dict),
        discarded_findings=[],
        warnings=[]
    )
    
    return validate_analysis(result, doc)
