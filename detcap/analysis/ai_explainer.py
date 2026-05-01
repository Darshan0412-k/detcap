import subprocess

class AIExplainer:
    def __init__(self, model="llama3"):
        self.model = model

    def build_prompt(self, services, cves, suggestions):
        return f"""
You are a cybersecurity analyst.

Services:
{services}

Vulnerabilities:
{cves}

Attack Insights:
{suggestions}

Explain clearly:
- What is running
- What risks exist
- What attacker might do (high level only)
- How to defend

Keep it structured and concise.
"""

    def explain(self, services, cves, suggestions):
        if not services:
            return "No services detected. Target may be filtered, offline, or blocking scans."

        prompt = self.build_prompt(services, cves, suggestions)

        try:
            result = subprocess.run(
                ["ollama", "run", self.model],
                input=prompt,
                text=True,
                capture_output=True,
                encoding="utf-8",
                errors="ignore"
            )

            return result.stdout.strip()

        except Exception as e:
            return f"[AI ERROR] {e}"