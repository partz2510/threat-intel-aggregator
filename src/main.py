# main.py
from dotenv import load_dotenv
import argparse
import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from services import query_virustotal, query_abuseipdb, query_otx_ip

load_dotenv()
console = Console()

def save_report(what, payload):
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    filename = out_dir / f"report-{what}.json"
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return str(filename)

def normalize_and_display(resource, results):
    # Build a simple table
    table = Table(title=f"Threat Intel | {resource}")
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta")
    table.add_column("Summary", style="white")
    for r in results:
        if not r.get("available"):
            table.add_row(r.get("source"), "[yellow]Unavailable[/yellow]", r.get("error",""))
            continue
        src = r.get("source")
        data = r.get("data", {})
        # Prepare a short summary depending on source
        if src == "VirusTotal":
            # pull reputation/last_analysis stats if present
            meta = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
            vt_score = meta.get("reputation", "N/A")
            summary = f"reputation={vt_score}"
        elif src == "AbuseIPDB":
            summary = f"abuseConfidenceScore={data.get('data', {}).get('abuseConfidenceScore', 'N/A')}" if isinstance(data, dict) else "N/A"
        elif src == "OTX":
            pulses = data.get("pulse_info", {}).get("count", 0) if isinstance(data, dict) else 0
            summary = f"pulses={pulses}"
        else:
            summary = "No summary"
        table.add_row(src, "[green]OK[/green]", summary)
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Threat Intel Aggregator - quick CLI")
    parser.add_argument("resource", help="IP / domain / file hash to check")
    parser.add_argument("--save", action="store_true", help="Save JSON combined report to reports/")
    args = parser.parse_args()
    resource = args.resource

    console.rule("[bold blue]Querying sources")
    results = []
    # VirusTotal (works for ip/domain/hash)
    vt = query_virustotal(resource)
    results.append(vt)

    # Try AbuseIPDB if looks like IP
    import ipaddress
    try:
        ipaddress.ip_address(resource)
        abuse = query_abuseipdb(resource)
        otx = query_otx_ip(resource)
        results.extend([abuse, otx])
    except ValueError:
        # not an IP — skip abuse/otx
        pass

    normalize_and_display(resource, results)

    if args.save:
        out = {"resource": resource, "results": results}
        path = save_report(resource, out)
        console.print(f"[bold green]Saved report:[/bold green] {path}")

if __name__ == "__main__":
    main()
