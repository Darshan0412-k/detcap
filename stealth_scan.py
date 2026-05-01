from scapy.all import IP, TCP, sr1
import random

class StealthScanner:
    def __init__(self, target, ports, timeout=1.5):
        self.target = target
        self.ports = ports
        self.timeout = timeout

    def scan_port(self, port):
        try:
            src_port = random.randint(1024, 65535)

            pkt = IP(dst=self.target) / TCP(
                sport=src_port,
                dport=port,
                flags="S"
            )

            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp is None:
                return port, "FILTERED"

            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags

                if flags == 0x12:  # SYN-ACK
                    # send RST (clean close)
                    rst = IP(dst=self.target) / TCP(
                        sport=src_port,
                        dport=port,
                        flags="R"
                    )
                    sr1(rst, timeout=0.5, verbose=0)
                    return port, "OPEN"

                elif flags == 0x14:  # RST-ACK
                    return port, "CLOSED"

            return port, "UNKNOWN"

        except:
            return port, "ERROR"

    def run(self):
        results = {}

        print(f"\n[*] Stealth SYN Scan on {self.target}\n")

        for port in self.ports:
            p, status = self.scan_port(port)
            results[p] = status
            print(f"[{status}] {p}")

        return results