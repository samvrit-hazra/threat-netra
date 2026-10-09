import pymupdf
import os
from fineprint.config import console

def highlight_quote(page, quote: str) -> bool:
    rects = page.search_for(quote)
    if rects:
        for r in rects:
            page.add_highlight_annot(r)
        return True
        
    words = quote.split()
    if len(words) > 5:
        half1 = " ".join(words[:len(words)//2])
        half2 = " ".join(words[len(words)//2:])
        found1 = highlight_quote(page, half1)
        found2 = highlight_quote(page, half2)
        return found1 or found2
        
    return False

def highlight_pdf(input_path: str, output_path: str, page_num: int, quote: str):
    doc = pymupdf.open(input_path)
    if 1 <= page_num <= len(doc):
        page = doc[page_num - 1]
        highlight_quote(page, quote)
        
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc.save(output_path)
    doc.close()
