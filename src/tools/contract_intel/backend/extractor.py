import hashlib
from typing import Tuple, List
import pymupdf
from src.tools.contract_intel.backend.schemas import Document, Page

def normalize_text_with_map(text: str) -> Tuple[str, List[int]]:
    """
    Normalizes text (lowercases, collapses whitespace, normalizes quotes/dashes,
    rejoins hyphenated line breaks) and returns the normalized string and a list 
    mapping each character in the normalized string to its original index in `text`.
    """
    norm_chars = []
    orig_indices = []
    
    i = 0
    n = len(text)
    in_whitespace = False
    
    while i < n:
        c = text[i]
        
        # hyphenated line break: '-\n' or '-\r\n'
        if c == '-' and i + 1 < n and text[i+1] in ('\n', '\r'):
            i += 1
            while i < n and text[i].isspace():
                i += 1
            continue
            
        if c.isspace():
            if not in_whitespace and len(norm_chars) > 0:
                norm_chars.append(' ')
                orig_indices.append(i)
                in_whitespace = True
            i += 1
            continue
            
        in_whitespace = False
        
        # map quotes/dashes
        if c in ('“', '”', '"'):
            nc = '"'
        elif c in ('‘', '’', "'"):
            nc = "'"
        elif c in ('—', '–', '-'):
            nc = '-'
        else:
            nc = c.lower()
            
        norm_chars.append(nc)
        orig_indices.append(i)
        i += 1
        
    if norm_chars and norm_chars[-1] == ' ':
        norm_chars.pop()
        orig_indices.pop()
        
    return "".join(norm_chars), orig_indices

def extract_pdf_bytes(pdf_bytes: bytes, filename: str = "document.pdf") -> Document:
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    pages = []
    
    for i in range(len(doc)):
        page = doc[i]
        text = page.get_text() or ""
        pages.append(Page(number=i+1, text=text))
        
    if not pages:
        pages.append(Page(number=1, text=""))
        
    return Document(path=filename, sha256=sha256, pages=pages)

def extract_text_document(raw_text: str, filename: str = "pasted_contract.txt") -> Document:
    sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    pages = []
    
    # Check for [[PAGE X]] markers
    if "[[PAGE " in raw_text:
        parts = raw_text.split("[[PAGE ")
        page_num = 1
        for part in parts:
            if not part.strip():
                continue
            header_end = part.find("]]")
            if header_end != -1:
                try:
                    num_str = part[:header_end].strip()
                    page_num = int(num_str)
                    content = part[header_end+2:].strip()
                except ValueError:
                    content = part.strip()
            else:
                content = part.strip()
            pages.append(Page(number=page_num, text=content))
            page_num += 1
    else:
        # Split into ~2000 character logical pages
        chunk_size = 2000
        paragraphs = raw_text.split("\n\n")
        current_page_text = []
        current_len = 0
        p_num = 1
        
        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
            if current_len + len(para) > chunk_size and current_page_text:
                pages.append(Page(number=p_num, text="\n\n".join(current_page_text)))
                p_num += 1
                current_page_text = [para]
                current_len = len(para)
            else:
                current_page_text.append(para)
                current_len += len(para)
                
        if current_page_text:
            pages.append(Page(number=p_num, text="\n\n".join(current_page_text)))
            
    if not pages:
        pages.append(Page(number=1, text=raw_text))
        
    return Document(path=filename, sha256=sha256, pages=pages)
