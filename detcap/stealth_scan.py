"""
DETCAP v1.0.1 — Stealth SYN Scanner
Threaded for performance; sends RST to cleanly close half-open connections.
"""

from __future__ import annotations
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn

try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class StealthScanner:
    def __init__(self, target: str, ports, timeout: float = 1.5, threads: int = 60):
        self.target = target
        self.ports = list(ports)
        self.timeout = timeout
        self.threads = threads

    def scan_port(self, port: int) -> tuple[int, str]:
        if not SCAPY_AVAILABLE:
            return port, "ERROR"
        try:
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=self.target) / TCP(
                sport=src_port,
                dport=port,
                flags="S",
            )
            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp is None:
                return port, "FILTERED"

            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                if flags == 0x12:  # SYN-ACK → OPEN
                    # Send RST to cleanly close half-open connection
                    rst = IP(dst=self.target) / TCP(
                        sport=src_port,
                        dport=port,
                        flags="R",
                    )
                    sr1(rst, timeout=0.5, verbose=0)
                    return port, "OPEN"
                elif flags == 0x14:  # RST-ACK → CLOSED
                    return port, "CLOSED"

            return port, "UNKNOWN"
        except Exception:
            return port, "ERROR"

    def run(self) -> dict[int, str]:
        results: dict[int, str] = {}
        open_count = 0

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]Stealth SYN scanning[/cyan] [bold]{task.description}[/bold]"),
            BarColumn(bar_width=30, style="cyan", complete_style="bright_cyan"),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task(self.target, total=len(self.ports))

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(self.scan_port, p): p for p in self.ports}
                for future in as_completed(futures):
                    port, status = future.result()
                    results[port] = status
                    if status == "OPEN":
                        open_count += 1
                    progress.advance(task)

        return results
