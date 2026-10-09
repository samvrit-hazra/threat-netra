import hashlib
import pymupdf
from fineprint.schemas import Document, Page
from fineprint.config import console

def normalize_text_with_map(text: str) -> tuple[str, list[int]]:
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
            if not in_whitespace and len(norm_chars) > 0: # don't start with space
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
        
    # strip trailing space
    if norm_chars and norm_chars[-1] == ' ':
        norm_chars.pop()
        orig_indices.pop()
        
    return "".join(norm_chars), orig_indices

def extract_pdf(path: str) -> Document:
    with open(path, "rb") as f:
        pdf_bytes = f.read()
    
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    pages = []
    
    for i in range(len(doc)):
        page = doc[i]
        text = page.get_text()
        
        if len(text.strip()) < 50:
            console.print(f"[bold yellow]Warning:[/bold yellow] Page {i+1} has almost no text; possibly scanned. OCR not supported.")
            
        pages.append(Page(number=i+1, text=text))
        
    return Document(path=path, sha256=sha256, pages=pages)
