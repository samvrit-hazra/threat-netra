import typer
import sys
from rich.panel import Panel
from typing import Optional
from fineprint.config import check_setup, console
from fineprint.llm import GroqClient, FakeLLM
from fineprint.offline import OfflineLLM
from fineprint.samples import make_samples as generate_samples
from fineprint.pdf_extract import extract_pdf
from fineprint.analyze import analyze_document
from fineprint.costs import calc_costs, format_inr
from fineprint.compare import compare_terms, generate_verdict
from fineprint.display import highlight_pdf
from fineprint.ask import ask_question
import json

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

app = typer.Typer(help="FinePrint — AI analyst for consumer contracts")

@app.command()
def check():
    """Validate API key and test connection to Gemma."""
    check_setup()
    console.print("[bold blue]Checking setup...[/bold blue]")
    client = GroqClient()
    success, models, response = client.check_connection()
    if success:
        console.print("[bold green]API key is valid![/bold green]")
    else:
        console.print("[bold red]API check failed![/bold red]")

@app.command()
def make_samples():
    """Generate sample PDF contracts for testing."""
    generate_samples()

@app.command()
def analyze(
    file: str, 
    json_out: Optional[str] = typer.Option(None, "--json"),
    show_unverified: bool = typer.Option(False, "--show-unverified"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    offline: bool = typer.Option(False, "--offline")
):
    """Analyze a contract PDF."""
    console.print(f"Analyzing {file}...")
    doc = extract_pdf(file)
    llm = OfflineLLM(file) if offline else GroqClient()
    
    result = analyze_document(doc, llm, use_cache=not no_cache)
    
    console.print(Panel(
        f"Pages analyzed: {len(doc.pages)}\n"
        f"Important findings: {len(result.findings)}\n"
        f"Financial conditions: {sum(1 for _, v in result.terms if v is not None)}\n"
        f"Items requiring attention: {sum(1 for f in result.findings if f.severity.value in ('high', 'medium'))}",
        title="[bold green]FinePrint Analysis Summary[/bold green]"
    ))
    
    # Sort findings by severity
    severity_order = {"high": 0, "medium": 1, "info": 2}
    result.findings.sort(key=lambda f: severity_order.get(f.severity.value, 3))
    
    for f in result.findings:
        color = "red" if f.severity.value == "high" else "yellow" if f.severity.value == "medium" else "blue"
        clause = f" · Clause {f.clause_ref}" if f.clause_ref else ""
        content = (
            f"[bold]Category:[/bold] {f.category.value}\n"
            f"[bold]Location:[/bold] Page {f.verified_page}{clause}\n\n"
            f"[bold]Explanation:[/bold] {f.explanation}\n"
            f"[bold]Why it matters:[/bold] {f.potential_consequence}\n\n"
            f"[bold green]✓ Verified Quote ({f.match_method}):[/bold green] \"{f.source_text}\"\n\n"
            f"[dim]Hint: run `fineprint source {file} {f.id}` to see original highlighted[/dim]"
        )
        console.print(Panel(content, title=f"[bold {color}]{f.id}: {f.title} ({f.severity.value.upper()})[/bold {color}]", border_style=color))
        
    console.print("\n[bold]Financial Costs:[/bold]")
    costs(file, offline=offline)
    
    if show_unverified and result.discarded_findings:
        console.print("\n[bold red]Unverified Findings (Discarded):[/bold red]")
        for f in result.discarded_findings:
            console.print(f"{f.id}: {f.title} - NO VERIFIED EVIDENCE")
            
    if json_out:
        with open(json_out, "w") as f:
            f.write(result.model_dump_json(indent=2))
            
    if offline:
        api_status = "[dim]API Status: Offline mode used (0 API calls).[/dim]"
    elif not no_cache:
        api_status = "[bold green]API Status: Live API / Cache successful (results retrieved).[/bold green]"
    else:
        api_status = "[bold green]API Status: Live API successful (results freshly generated).[/bold green]"
        
    console.print(f"\n{api_status}")
    console.print("[italic dim]Informational document analysis only. Not legal advice.[/italic dim]")

@app.command()
def costs(file: str, cancel_after_month: Optional[int] = None, offline: bool = typer.Option(False, "--offline")):
    doc = extract_pdf(file)
    llm = OfflineLLM(file) if offline else GroqClient()
    result = analyze_document(doc, llm)
    lines = calc_costs(result.terms, cancel_after_month)
    for line in lines:
        amt = format_inr(line.amount) if line.amount is not None else line.missing_reason
        console.print(f"{line.label}: {amt} (Sources: {','.join(line.sources)})")

@app.command()
def compare(file_a: str, file_b: str, offline: bool = typer.Option(False, "--offline")):
    doc_a = extract_pdf(file_a)
    llm_a = OfflineLLM(file_a) if offline else GroqClient()
    res_a = analyze_document(doc_a, llm_a)
    doc_b = extract_pdf(file_b)
    llm_b = OfflineLLM(file_b) if offline else GroqClient()
    res_b = analyze_document(doc_b, llm_b)
    
    rows = compare_terms(res_a.terms, res_b.terms)
    
    from rich.table import Table
    table = Table(title="Contract Comparison", show_header=True, header_style="bold magenta")
    table.add_column("Term", style="cyan")
    table.add_column("Plan A", style="green")
    table.add_column("Plan B", style="green")
    table.add_column("Difference", justify="center")
    
    for r in rows:
        diff_str = "[red]Yes[/red]" if r['diff'] else "[dim]No[/dim]"
        a_str = f"{r['A_val']} [dim]({r['A_ev']})[/dim]" if r['A_ev'] else str(r['A_val'])
        b_str = f"{r['B_val']} [dim]({r['B_ev']})[/dim]" if r['B_ev'] else str(r['B_val'])
        table.add_row(r['label'], a_str, b_str, diff_str)
        
    console.print(table)
        
    verdict = generate_verdict(rows, llm_a)
    console.print(Panel(verdict, title="[bold]AI Verdict[/bold]"))
    console.print("\n[italic dim]Informational document analysis only. Not legal advice.[/italic dim]")

@app.command()
def source(file: str, finding_id: str, open_pdf: bool = False):
    doc = extract_pdf(file)
    llm = FakeLLM()
    result = analyze_document(doc, llm)
    
    f = next((x for x in result.findings if x.id == finding_id), None)
    if not f:
        console.print("Finding not found or not verified.")
        return
        
    out_path = f"output/{finding_id}_highlighted.pdf"
    highlight_pdf(file, out_path, f.verified_page, f.source_text)
    console.print(f"Highlighted quote in {out_path}")

@app.command()
def ask(file: str, question: str):
    doc = extract_pdf(file)
    llm = GroqClient()
    answer = ask_question(doc, question, llm)
    console.print(f"\n[bold]Answer:[/bold]\n{answer}")

@app.command()
def demo(offline: bool = typer.Option(False, "--offline")):
    console.print("[bold]Running FinePrint Demo[/bold]")
    generate_samples()
    analyze("samples/PlanA.pdf", json_out=None, show_unverified=False, no_cache=False, offline=offline)
    console.print("\n[bold]Costs for Plan A:[/bold]")
    costs("samples/PlanA.pdf", cancel_after_month=None, offline=offline)
    console.print("\n[bold]Comparing Plan A and Plan B:[/bold]")
    compare("samples/PlanA.pdf", "samples/PlanB.pdf", offline=offline)

if __name__ == "__main__":
    app()
