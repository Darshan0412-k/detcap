from scapy.all import IP, TCP, sr1


class FingerprintEngine:

    def detect_os(self, ip):

        try:

            packet = IP(dst=ip) / TCP(
                dport=80,
                flags="S"
            )

            response = sr1(
                packet,
                timeout=1,
                verbose=0
            )

            if not response:

                return {
                    "os": "Unknown / Filtered",
                    "confidence": 20
                }

            ttl = response.ttl

            tcp_layer = response.getlayer(TCP)

            window_size = tcp_layer.window

            # Basic TTL fingerprinting

            if ttl <= 64:
                os_guess = "Linux / Unix"

            elif ttl <= 128:
                os_guess = "Windows"

            else:
                os_guess = "Network Device"

            confidence = 70

            # Window size bonus confidence

            if window_size in [64240, 65535]:

                confidence += 15

            return {
                "os": os_guess,
                "confidence": confidence,
                "ttl": ttl,
                "window": window_size
            }

        except:

            return {
                "os": "Unknown",
                "confidence": 0
            }

    def service_fingerprint(self, ip, port):

        try:

            packet = IP(dst=ip) / TCP(
                dport=port,
                flags="S"
            )

            response = sr1(
                packet,
                timeout=1,
                verbose=0
            )

            if not response:

                return {
                    "state": "filtered",
                    "confidence": 0
                }

            if response.haslayer(TCP):

                tcp_flags = response.getlayer(TCP).flags

                # SYN ACK = open

                if tcp_flags == 0x12:

                    return {
                        "state": "open",
                        "confidence": 95
                    }

                # RST ACK = closed

                elif tcp_flags == 0x14:

                    return {
                        "state": "closed",
                        "confidence": 90
                    }

            return {
                "state": "unknown",
                "confidence": 50
            }

        except:

            return {
                "state": "error",
                "confidence": 0
            }