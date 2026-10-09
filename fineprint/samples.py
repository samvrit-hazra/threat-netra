import pymupdf
import os
from fineprint.config import console

def create_sample_a(output_path: str):
    doc = pymupdf.open()
    
    for i in range(12):
        page = doc.new_page()
        page.insert_text((50, 50), "FICTIONAL - FOR DEMO", fontsize=10, color=(1,0,0))
        text = f"Page {i+1} filler legal text for StreamNova Premium contract.\nWe value your privacy and limit liability as permitted by law.\n" * 15
        page.insert_text((50, 80), text, fontsize=11)
        
    doc[0].insert_text((50, 400), "Welcome to StreamNova Premium.\nThe cost is Rs. 999/month with a 12-month minimum term.\nThere is a one-time Rs. 500 setup fee, non-refundable.", fontsize=11)
    
    doc[3].insert_text((50, 400), "3.1 Refunds\nRefunds are restricted. They are only provided for an outage over 7 consecutive days.", fontsize=11)
    
    doc[6].insert_text((50, 400), "8.2 Term and Renewal\nThis contract auto-renews for successive 12-month terms at Rs. 1,199/month unless written notice is given >=30 days before term end.", fontsize=11)
    
    doc[8].insert_text((50, 400), "11.4 Early Termination\nIf you terminate early, the early termination fee equals 50% of remaining monthly fees.", fontsize=11)
    
    doc.save(output_path)
    doc.close()

def create_sample_b(output_path: str):
    doc = pymupdf.open()
    
    for i in range(12):
        page = doc.new_page()
        page.insert_text((50, 50), "FICTIONAL - FOR DEMO", fontsize=10, color=(1,0,0))
        text = f"Page {i+1} filler legal text for ClearConnect Flexible contract.\nData sharing and liability cap sections apply.\n" * 15
        page.insert_text((50, 80), text, fontsize=11)
        
    doc[0].insert_text((50, 400), "Welcome to ClearConnect Flexible.\nMonthly price is Rs. 1,199/month for a 12-month term.\nThere is no setup fee.", fontsize=11)
    
    doc[6].insert_text((50, 400), "8.2 Term and Renewal\nThere is no auto-renewal. The contract simply ends at term end.", fontsize=11)
    
    doc[8].insert_text((50, 400), "11.4 Cancellation and Refunds\nRequires a 7-day cancellation notice.\nThere is no early termination fee.\nYou may receive a pro-rated refund of unused prepaid fees within the first 30 days.", fontsize=11)
    
    doc.save(output_path)
    doc.close()

def verify_samples():
    doc_a = pymupdf.open("samples/PlanA.pdf")
    assert "999" in doc_a[0].get_text()
    assert "Refunds are restricted" in doc_a[3].get_text()
    assert "auto-renews" in doc_a[6].get_text()
    assert "50%" in doc_a[8].get_text()
    doc_a.close()
    
    doc_b = pymupdf.open("samples/PlanB.pdf")
    assert "1,199" in doc_b[0].get_text()
    assert "no auto-renewal" in doc_b[6].get_text()
    assert "7-day cancellation" in doc_b[8].get_text()
    doc_b.close()

def make_samples():
    os.makedirs("samples", exist_ok=True)
    create_sample_a("samples/PlanA.pdf")
    create_sample_b("samples/PlanB.pdf")
    verify_samples()
    console.print("[green]Samples generated successfully and verified in samples/ directory.[/green]")
