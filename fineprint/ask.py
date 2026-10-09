from pydantic import BaseModel
from typing import List, Optional
from fineprint.schemas import Document, Finding
from fineprint.llm import LLMClient
from fineprint.config import MAX_CHARS_PER_CALL
from fineprint.analyze import chunk_document
from fineprint.validate import validate_finding

class Citation(BaseModel):
    page: int
    quote: str

class AskResponse(BaseModel):
    answerable: bool
    answer: str
    citations: List[Citation]

def ask_question(doc: Document, question: str, llm: LLMClient) -> str:
    chunks = chunk_document(doc, MAX_CHARS_PER_CALL)
    chunk = chunks[0] if chunks else ""
    
    prompt = f"""You are an AI analyst. Answer the user's question based ONLY on the document provided.
Question: {question}

If the document does not contain the answer, set answerable to false.
Provide citations with the exact quote and page number. The quote MUST be an exact substring of the document text.
The document text uses [[PAGE X]] markers.

Document Text:
{chunk}
"""
    
    try:
        resp = llm.generate_json(prompt, AskResponse)
        ask_data = AskResponse(**resp)
    except Exception:
        return "The document does not provide enough information to answer this confidently."
        
    if not ask_data.answerable or not ask_data.citations:
        return "The document does not provide enough information to answer this confidently."
        
    verified_citations = []
    for c in ask_data.citations:
        f = Finding(id="C1", category="fees", severity="info", title="citation", 
                   page=c.page, source_text=c.quote, explanation="", potential_consequence="")
        v = validate_finding(f, doc)
        if v.verified:
            verified_citations.append(v)
            
    if not verified_citations:
        return "The document does not provide enough information to answer this confidently."
        
    out = ask_data.answer + "\n\nCitations:\n"
    for v in verified_citations:
        out += f"- \"{v.source_text}\" (Page {v.verified_page})\n"
        
    return out
