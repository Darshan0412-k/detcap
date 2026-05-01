from core.scanner import PortScanner
from core.service_detector import ServiceDetector
from analysis.cve_mapper import CVEMapper
from analysis.attack_advisor import AttackAdvisor
from analysis.ai_explainer import AIExplainer
from analysis.fingerprint import FingerprintEngine
from stealth_scan import StealthScanner

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

import re
import os
from datetime import datetime


def main():

    console = Console()

    fp = FingerprintEngine()

    # =========================
    # INPUT
    # =========================

    target = Prompt.ask(
        "Enter target IP",
        default="127.0.0.1"
    )

    profiles = {
        "fast": {
            "ports": range(1, 201),
            "threads": 100,
            "timeout": 1
        },

        "balanced": {
            "ports": range(1, 1025),
            "threads": 80,
            "timeout": 2
        },

        "full": {
            "ports": range(1, 65536),
            "threads": 120,
            "timeout": 2
        }
    }

    profile_name = Prompt.ask(
        "Select scan profile (fast / balanced / full)",
        default="balanced"
    ).lower()

    if profile_name not in profiles:
        console.print(
            "[red]Invalid profile. Using balanced[/red]"
        )
        profile_name = "balanced"

    profile = profiles[profile_name]

    mode = Prompt.ask(
        "Scan mode (normal / stealth)",
        default="normal"
    ).lower()

    console.print(
        f"\n[bold cyan]🚀 DETCAP Scan Started on {target}[/bold cyan]"
    )

    console.print(
        f"[bold yellow]Profile: {profile_name} | Mode: {mode}[/bold yellow]\n"
    )

    # =========================
    # OS DETECTION
    # =========================

    os_info = fp.detect_os(target)

    console.print(
        f"[bold green]🧠 OS Guess: "
        f"{os_info['os']} "
        f"({os_info['confidence']}% confidence)"
        f"[/bold green]\n"
    )

    # =========================
    # SCAN ENGINE
    # =========================

    open_ports = []

    if mode == "stealth":

        console.print(
            "\n[bold magenta]Running Stealth SYN Scan...[/bold magenta]\n"
        )

        scanner = StealthScanner(
            target,
            profile["ports"],
            timeout=profile["timeout"]
        )

        scan_results = scanner.run()

        open_ports = [
            port for port, state in scan_results.items()
            if state == "OPEN"
        ]

    else:

        scanner = PortScanner(
            target,
            profile["ports"],
            timeout=profile["timeout"],
            threads=profile["threads"]
        )

        open_ports = scanner.run()

    # =========================
    # NO OPEN PORTS
    # =========================

    if not open_ports:

        console.print(
            "\n[bold red]⚠️ No open ports found.[/bold red]"
        )

        console.print(
            "[yellow]Target may be filtered or blocking scans.[/yellow]\n"
        )

    # =========================
    # SERVICE DETECTION
    # =========================

    detector = ServiceDetector()

    services = [
        detector.detect(target, p)
        for p in open_ports
    ]

    service_table = Table(
        title="🛰️ Services Detected"
    )

    service_table.add_column(
        "Port",
        style="cyan"
    )

    service_table.add_column(
        "Service",
        style="green"
    )

    service_table.add_column(
        "Version",
        style="yellow"
    )

    for s in services:

        fingerprint = fp.service_fingerprint(
            target,
            s["port"]
        )

        service_table.add_row(
            str(s["port"]),
            f"{s['service']} ({fingerprint['state']})",
            f"{s['version'][:25]} | "
            f"Conf: {fingerprint['confidence']}%"
        )

    console.print(service_table)

    # =========================
    # CVE MAPPING
    # =========================

    cve_mapper = CVEMapper()

    cve_results = [
        cve_mapper.match(
            s["service"],
            s["version"]
        )
        for s in services
    ]

    flat_cves = []
    seen = set()

    for cves in cve_results:

        for cve in cves:

            if cve["cve"] not in seen:

                seen.add(cve["cve"])
                flat_cves.append(cve)

    cve_table = Table(
        title="⚠️ Vulnerabilities (CVEs)"
    )

    cve_table.add_column(
        "CVE",
        style="red"
    )

    cve_table.add_column("Severity")

    cve_table.add_column("Description")

    for c in flat_cves:

        cve_table.add_row(
            c["cve"],
            c["severity"],
            c["description"]
        )

    console.print(cve_table)

    # =========================
    # ATTACK INSIGHTS
    # =========================

    advisor = AttackAdvisor()

    suggestions = advisor.suggest(
        services,
        cve_results
    )

    attack_table = Table(
        title="⚔️ Attack Insights"
    )

    attack_table.add_column("Service")
    attack_table.add_column("Risk")
    attack_table.add_column("Defense")

    for s in suggestions:

        attack_table.add_row(
            s.get("service", "-"),
            s.get("risk", "-"),
            s.get("defense", "-")
        )

    console.print(attack_table)

    # =========================
    # AI ANALYSIS
    # =========================

    ai = AIExplainer()

    console.print(
        "\n[bold magenta]🧠 AI ANALYSIS[/bold magenta]\n"
    )

    raw_output = ai.explain(
        services,
        cve_results,
        suggestions
    )

    clean_output = re.sub(
        r'\[[0-9;]*[A-Za-z]',
        '',
        raw_output
    )

    console.print(

        Panel.fit(
            clean_output,
            title="AI Security Report",
            border_style="magenta"
        )
    )

    # =========================
    # REPORT GENERATION
    # =========================

    os.makedirs(
        "reports",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    html_file = (
        f"reports/report_{target}_{timestamp}.html"
    )

    with open(
        html_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            f"<pre>{clean_output}</pre>"
        )

    console.print(
        f"\n[green]📄 Report saved: {html_file}[/green]"
    )


if __name__ == "__main__":
    main()