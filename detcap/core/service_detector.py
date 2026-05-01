from ..utils.banner import grab_banner

class ServiceDetector:
    def detect(self, target, port):
        banner = grab_banner(target, port)

        service = "unknown"
        version = "unknown"

        # 🔥 Banner-based detection
        if "SSH" in banner:
            service = "ssh"
            version = banner

        elif "HTTP" in banner:
            service = "http"
            version = banner

        elif "VMware" in banner:
            service = "vmware-auth"
            version = banner

        # ⚡ Port-based fallback detection
        elif port == 80:
            service = "http"
        elif port == 443:
            service = "https"
        elif port == 21:
            service = "ftp"
        elif port == 22:
            service = "ssh"
        elif port == 445:
            service = "smb"
        elif port == 135:
            service = "rpc"

        return {
            "port": port,
            "service": service,
            "version": version,
            "banner": banner
        }