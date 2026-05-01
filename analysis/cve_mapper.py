import json

class CVEMapper:
    def __init__(self, db_path="data/cve_db.json"):
        try:
            with open(db_path, "r") as f:
                self.cve_db = json.load(f)
        except:
            self.cve_db = {}

    def match(self, service, version):
        matches = []

        if service in self.cve_db:
            for entry in self.cve_db[service]:
                if entry["version"] == "" or entry["version"] in version:
                    matches.append(entry)

        return matches