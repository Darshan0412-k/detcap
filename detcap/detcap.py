"""
DETCAP v1.0.1 — AI-Powered Network Reconnaissance & Security Analysis Tool
Author: Darshan G
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from analysis.ai_explainer import AIExplainer
from analysis.attack_advisor import AttackAdvisor
from analysis.cve_mapper import CVEMapper
from analysis.fingerprint import FingerprintEngine
from core.scanner import PortScanner
from core.service_detector import ServiceDetector
from report_generator import generate_html_report
from stealth_scan import StealthScanner

VERSION = "1.0.1"

PROFILES = {
    "fast": {"ports": range(1, 201), "threads": 100, "timeout": 1},
    "balanced": {"ports": range(1, 1025), "threads": 80, "timeout": 2},
    "full": {"ports": range(1, 65536), "threads": 120, "timeout": 2},
}


def validate_target(target: str) -> str:
    """Validate IP address or hostname. Returns cleaned target or raises ValueError."""
    target = target.strip()
    # Try as IP first
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    # Basic hostname validation
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if hostname_re.match(target):
        return target
    raise ValueError(f"Invalid target: '{target}'. Must be a valid IP or hostname.")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="detcap",
        description="DETCAP v{} — AI-Powered Network Recon Tool".format(VERSION),
    )
    parser.add_argument("-t", "--target", help="Target IP address or hostname")
    parser.add_argument(
        "-p",
        "--profile",
        choices=["fast", "balanced", "full"],
        default="balanced",
        help="Scan profile (default: balanced)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["normal", "stealth"],
        default="normal",
        help="Scan mode (default: normal)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Also export results as JSON"
    )
    parser.add_argument(
        "--no-ai", action="store_true", help="Skip AI analysis (faster)"
    )
    return parser.parse_args()


def run_scan(console, target, profile_name, mode, export_json, no_ai):
    profile = PROFILES[profile_name]
    fp = FingerprintEngine()

    console.print(
        Panel.fit(
            f"[bold cyan]DETCAP v{VERSION}[/bold cyan]\n"
            f"[white]Target:[/white] [yellow]{target}[/yellow]  "
            f"[white]Profile:[/white] [yellow]{profile_name}[/yellow]  "
            f"[white]Mode:[/white] [yellow]{mode}[/yellow]",
            border_style="cyan",
        )
    )

    # ── OS Detection ──────────────────────────────────────────────────────
    os_info = fp.detect_os(target)
    console.print(
        f"\n[bold green]🧠 OS Guess:[/bold green] "
        f"{os_info['os']} ({os_info['confidence']}% confidence)\n"
    )

    # ── Scan ──────────────────────────────────────────────────────────────
    open_ports = []
    if mode == "stealth":
        console.print("[bold magenta]Running Stealth SYN Scan...[/bold magenta]\n")
        scanner = StealthScanner(target, profile["ports"], timeout=profile["timeout"])
        scan_results = scanner.run()
        open_ports = [p for p, s in scan_results.items() if s == "OPEN"]
    else:
        scanner = PortScanner(
            target,
            profile["ports"],
            timeout=profile["timeout"],
            threads=profile["threads"],
        )
        open_ports = scanner.run()

    if not open_ports:
        console.print("\n[bold red]⚠️  No open ports found.[/bold red]")
        console.print("[yellow]Target may be filtered or blocking scans.[/yellow]\n")

    # ── Service Detection ─────────────────────────────────────────────────
    detector = ServiceDetector()
    services = [detector.detect(target, p) for p in open_ports]

    svc_table = Table(title="🛰️  Services Detected", border_style="cyan")
    svc_table.add_column("Port", style="cyan", no_wrap=True)
    svc_table.add_column("Service", style="green")
    svc_table.add_column("Version", style="yellow")
    svc_table.add_column("State", style="white")
    svc_table.add_column("Confidence", style="magenta")

    for s in services:
        fp_result = fp.service_fingerprint(target, s["port"])
        svc_table.add_row(
            str(s["port"]),
            s["service"],
            s["version"][:30] if s["version"] else "—",
            fp_result["state"],
            f"{fp_result['confidence']}%",
        )
    console.print(svc_table)

    # ── CVE Mapping ───────────────────────────────────────────────────────
    cve_mapper = CVEMapper()
    cve_results = [cve_mapper.match(s["service"], s["version"]) for s in services]

    flat_cves = []
    seen = set()
    for cves in cve_results:
        for cve in cves:
            if cve["cve"] not in seen:
                seen.add(cve["cve"])
                flat_cves.append(cve)

    sev_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}

    cve_table = Table(title="⚠️  Vulnerabilities (CVEs)", border_style="red")
    cve_table.add_column("CVE ID", style="red", no_wrap=True)
    cve_table.add_column("Severity")
    cve_table.add_column("Description")

    for c in flat_cves:
        color = sev_colors.get(c["severity"].upper(), "white")
        cve_table.add_row(
            c["cve"],
            f"[{color}]{c['severity']}[/{color}]",
            c["description"],
        )
    console.print(cve_table)

    # ── Attack Insights ───────────────────────────────────────────────────
    advisor = AttackAdvisor()
    suggestions = advisor.suggest(services, cve_results)

    atk_table = Table(title="⚔️  Attack Insights", border_style="yellow")
    atk_table.add_column("Service", style="cyan")
    atk_table.add_column("Risk", style="red")
    atk_table.add_column("Defense", style="green")

    for s in suggestions:
        atk_table.add_row(s.get("service", "—"), s.get("risk", "—"), s.get("defense", "—"))
    console.print(atk_table)

    # ── AI Analysis ───────────────────────────────────────────────────────
    ai_report = ""
    if not no_ai:
        console.print("\n[bold magenta]🧠 Running AI Analysis (Ollama)...[/bold magenta]\n")
        ai = AIExplainer()
        raw_output = ai.explain(services, cve_results, suggestions)
        # Fixed regex: was missing * quantifier escape
        ai_report = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw_output)
        console.print(
            Panel.fit(ai_report, title="AI Security Report", border_style="magenta")
        )

    # ── Reports ───────────────────────────────────────────────────────────
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"reports/detcap_{target.replace('.', '_')}_{timestamp}"

    # HTML Report
    html_path = base_name + ".html"
    generate_html_report(
        path=html_path,
        target=target,
        profile_name=profile_name,
        mode=mode,
        os_info=os_info,
        services=services,
        flat_cves=flat_cves,
        suggestions=suggestions,
        ai_report=ai_report,
        timestamp=timestamp,
        version=VERSION,
    )
    console.print(f"\n[bold green]📄 HTML Report:[/bold green] {html_path}")

    # JSON Export (optional)
    if export_json:
        json_path = base_name + ".json"
        data = {
            "meta": {"version": VERSION, "target": target, "timestamp": timestamp,
                     "profile": profile_name, "mode": mode},
            "os": os_info,
            "services": services,
            "cves": flat_cves,
            "attack_insights": suggestions,
            "ai_report": ai_report,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        console.print(f"[bold green]📦 JSON Export:[/bold green]  {json_path}")


def main():
    console = Console()
    args = parse_args()

    # Interactive mode if no target given via CLI
    if args.target:
        try:
            target = validate_target(args.target)
        except ValueError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            sys.exit(1)
        profile_name = args.profile
        mode = args.mode
        export_json = args.json
        no_ai = args.no_ai
    else:
        # Interactive prompts
        while True:
            raw = Prompt.ask("Enter target IP or hostname", default="127.0.0.1")
            try:
                target = validate_target(raw)
                break
            except ValueError as e:
                console.print(f"[red]{e}[/red]")

        profile_name = Prompt.ask(
            "Select scan profile (fast / balanced / full)", default="balanced"
        ).lower()
        if profile_name not in PROFILES:
            console.print("[red]Invalid profile. Using balanced.[/red]")
            profile_name = "balanced"

        mode = Prompt.ask("Scan mode (normal / stealth)", default="normal").lower()
        if mode not in ("normal", "stealth"):
            mode = "normal"

        export_json = Prompt.ask("Export JSON? (y/n)", default="n").lower() == "y"
        no_ai = Prompt.ask("Skip AI analysis? (y/n)", default="n").lower() == "y"

    run_scan(console, target, profile_name, mode, export_json, no_ai)


if __name__ == "__main__":
    main()
