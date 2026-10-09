import os
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from src.auth.backend.dependencies import require_approved_user
from src.tools.contract_intel.backend.schemas import (
    AnalysisResult, AskRequest, AskResponse, CompareRequest, CompareResult
)
from src.tools.contract_intel.backend.extractor import extract_pdf_bytes, extract_text_document
from src.tools.contract_intel.backend.engine import (
    analyze_contract_doc, answer_contract_question, compare_contracts
)
from src.tools.contract_intel.backend.samples import SAMPLE_CONTRACTS

logger = logging.getLogger("contract_intel.router")

router = APIRouter(prefix="/tools/contract_intel", tags=["contract_intel"])
templates = Jinja2Templates(directory="src")

class AnalyzePayload(BaseModel):
    raw_text: Optional[str] = None
    doc_name: Optional[str] = "Contract Document"
    provider: Optional[str] = "auto"

# In-memory document session cache so Q&A can reference the active document
DOC_CACHE: Dict[str, Any] = {}
LAST_ACTIVE_DOC: Dict[str, Any] = {}

# -------------------------------------------------------------------------
# UI ROUTE
# -------------------------------------------------------------------------
@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def read_contract_intel_ui(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """Renders the Defense-grade Contract & Document Intelligence Dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="tools/contract_intel/frontend/index.html",
        context={
            "user": current_user,
            "samples": list(SAMPLE_CONTRACTS.values())
        }
    )

# -------------------------------------------------------------------------
# SAMPLES ENDPOINTS
# -------------------------------------------------------------------------
@router.get("/api/samples")
async def get_samples(current_user: dict = Depends(require_approved_user)):
    return list(SAMPLE_CONTRACTS.values())

@router.get("/api/sample/{sample_id}")
async def get_sample_content(sample_id: str, current_user: dict = Depends(require_approved_user)):
    sample = SAMPLE_CONTRACTS.get(sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample contract not found.")
    return sample

@router.post("/api/analyze-sample/{sample_id}")
async def api_analyze_sample(
    sample_id: str,
    provider: str = "auto",
    current_user: dict = Depends(require_approved_user)
):
    sample = SAMPLE_CONTRACTS.get(sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample contract not found.")
    doc = extract_text_document(sample["text"], filename=sample["name"])
    DOC_CACHE[doc.sha256] = doc
    LAST_ACTIVE_DOC["current"] = doc
    result = analyze_contract_doc(doc, provider=provider)
    return result.model_dump()

# -------------------------------------------------------------------------
# PDF UPLOAD & FORENSIC ANALYSIS
# -------------------------------------------------------------------------
@router.post("/api/upload")
async def api_upload_pdf(
    file: UploadFile = File(...),
    provider: str = Form("auto"),
    current_user: dict = Depends(require_approved_user)
):
    try:
        filename_lower = file.filename.lower()
        if not filename_lower.endswith((".pdf", ".txt")):
            raise HTTPException(status_code=400, detail="Only PDF document files (.pdf) are supported.")
            
        contents = await file.read()
        if len(contents) > 25 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size exceeds maximum 25MB threshold.")
            
        if filename_lower.endswith(".pdf"):
            doc = extract_pdf_bytes(contents, filename=file.filename)
        else:
            doc = extract_text_document(contents.decode("utf-8", errors="replace"), filename=file.filename)
            
        DOC_CACHE[doc.sha256] = doc
        LAST_ACTIVE_DOC["current"] = doc
        result = analyze_contract_doc(doc, provider=provider)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing contract file upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/analyze")
async def api_analyze_contract(
    payload: AnalyzePayload,
    current_user: dict = Depends(require_approved_user)
):
    try:
        text = (payload.raw_text or "").strip()
        if not text:
            raise HTTPException(status_code=400, detail="No document provided. Please upload a PDF file.")
            
        doc = extract_text_document(text, filename=payload.doc_name or "contract.txt")
        DOC_CACHE[doc.sha256] = doc
        LAST_ACTIVE_DOC["current"] = doc
        
        result = analyze_contract_doc(doc, provider=payload.provider or "auto")
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing contract: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------------
# INTERACTIVE Q&A ENDPOINT
# -------------------------------------------------------------------------
@router.post("/api/ask")
async def api_ask_question(
    req: AskRequest,
    current_user: dict = Depends(require_approved_user)
):
    try:
        doc = None
        if req.sha256 and req.sha256 in DOC_CACHE:
            doc = DOC_CACHE[req.sha256]
        elif req.raw_text:
            doc = extract_text_document(req.raw_text.strip(), filename="query_doc.txt")
            DOC_CACHE[doc.sha256] = doc
        elif "current" in LAST_ACTIVE_DOC:
            doc = LAST_ACTIVE_DOC["current"]
            
        if not doc:
            raise HTTPException(status_code=400, detail="No active contract found in session. Please upload a PDF document first.")
            
        res = answer_contract_question(doc, req.question)
        return res.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during contract Q&A: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------------
# DUAL CONTRACT COMPARISON (FILES & SAMPLES)
# -------------------------------------------------------------------------
@router.post("/api/compare-upload")
async def api_compare_upload(
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...),
    provider: str = Form("auto"),
    current_user: dict = Depends(require_approved_user)
):
    try:
        contents_a = await file_a.read()
        contents_b = await file_b.read()
        
        if file_a.filename.lower().endswith(".pdf"):
            doc_a = extract_pdf_bytes(contents_a, filename=file_a.filename)
        else:
            doc_a = extract_text_document(contents_a.decode("utf-8", errors="replace"), filename=file_a.filename)
            
        if file_b.filename.lower().endswith(".pdf"):
            doc_b = extract_pdf_bytes(contents_b, filename=file_b.filename)
        else:
            doc_b = extract_text_document(contents_b.decode("utf-8", errors="replace"), filename=file_b.filename)
            
        res = compare_contracts(doc_a, doc_b, name_a=file_a.filename, name_b=file_b.filename, provider=provider)
        return res.model_dump()
    except Exception as e:
        logger.error(f"Error during compare upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/compare")
async def api_compare_contracts(
    req: CompareRequest,
    current_user: dict = Depends(require_approved_user)
):
    try:
        doc_a = extract_text_document(req.text_a.strip(), filename=req.name_a or "Contract A")
        doc_b = extract_text_document(req.text_b.strip(), filename=req.name_b or "Contract B")
        
        res = compare_contracts(doc_a, doc_b, name_a=req.name_a or "Contract A", name_b=req.name_b or "Contract B")
        return res.model_dump()
    except Exception as e:
        logger.error(f"Error during contract comparison: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
