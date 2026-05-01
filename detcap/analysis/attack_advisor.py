class AttackAdvisor:
    def suggest(self, services, cve_results):
        suggestions = []

        for s in services:
            name = s["service"]
            port = s["port"]

            if name == "smb":
                suggestions.append({
                    "service": "smb",
                    "port": port,
                    "risk": "SMB vulnerability exposure",
                    "defense": "Disable SMBv1, patch system"
                })

            elif name == "rpc":
                suggestions.append({
                    "service": "rpc",
                    "port": port,
                    "risk": "Remote execution risk",
                    "defense": "Restrict access, update OS"
                })

            elif name == "vmware-auth":
                suggestions.append({
                    "service": "vmware-auth",
                    "port": port,
                    "risk": "VMware service exposure",
                    "defense": "Restrict access"
                })

        for cves in cve_results:
            for cve in cves:
                suggestions.append({
                    "service": "cve",
                    "risk": f"{cve['cve']} vulnerability",
                    "defense": "Apply patches"
                })

        return suggestions