import socket
import time
import platform
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, target, ports, timeout=2, threads=80, retries=2):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.retries = retries

    # =========================
    # TCP SCAN
    # =========================
    def scan_tcp(self, port):
        status = "filtered"
        banner = ""

        for _ in range(self.retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                result = sock.connect_ex((self.target, port))

                if result == 0:
                    status = "open"

                    try:
                        sock.send(b"HELLO\r\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                    except:
                        pass

                    sock.close()
                    break

                elif result == 111 or result == 10061:
                    status = "closed"
                    sock.close()
                    break

                sock.close()

            except:
                status = "filtered"

        return {
            "port": port,
            "protocol": "tcp",
            "status": status,
            "banner": banner
        }

    # =========================
    # UDP SCAN (BEST EFFORT)
    # =========================
    def scan_udp(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # generic UDP probe
            sock.sendto(b"DETCAP_PROBE", (self.target, port))

            try:
                data, _ = sock.recvfrom(1024)
                return {
                    "port": port,
                    "protocol": "udp",
                    "status": "open|response",
                    "banner": data.decode(errors="ignore")
                }
            except:
                return {
                    "port": port,
                    "protocol": "udp",
                    "status": "open|no-response",
                    "banner": ""
                }

        except:
            return {
                "port": port,
                "protocol": "udp",
                "status": "filtered",
                "banner": ""
            }

    # =========================
    # OS FINGERPRINT (TTL HEURISTIC)
    # =========================
    def os_guess(self, ttl):
        if ttl <= 64:
            return "Linux / Unix-like"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Network Device / Unknown"

    # =========================
    # MAIN RUN
    # =========================
    def run(self):
        results = []
        open_ports = []

        print("\n[+] TCP Scan Starting...\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tcp_results = list(executor.map(self.scan_tcp, self.ports))

        for r in tcp_results:
            if r["status"] == "open":
                print(f"[TCP OPEN] {r['port']}")
                open_ports.append(r["port"])
            results.append(r)

        # UDP scan only on common ports (faster + realistic)
        udp_ports = [53, 67, 68, 123, 161, 500]

        print("\n[+] UDP Probe Scan...\n")

        for p in udp_ports:
            u = self.scan_udp(p)
            results.append(u)

        # OS detection (simple TTL check using ping)
        try:
            print("\n[+] OS Fingerprint...\n")

            if platform.system().lower() == "windows":
                cmd = f"ping -n 1 {self.target}"
            else:
                cmd = f"ping -c 1 {self.target}"

            import subprocess
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

            ttl = 64  # default fallback

            for line in out.splitlines():
                if "TTL=" in line or "ttl=" in line:
                    try:
                        ttl = int(line.split("TTL=")[-1].split()[0])
                    except:
                        pass

            os_guess = self.os_guess(ttl)
            print(f"[OS GUESS] {os_guess} (TTL={ttl})")

            results.append({
                "os_guess": os_guess,
                "ttl": ttl
            })

        except:
            print("[OS GUESS] Failed")

        return open_ports