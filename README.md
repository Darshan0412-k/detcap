# DETCAP


## 👥 Built by The Commit Crew

- Darshan G
- Shriman P
- Gokul Anandh T
- Jana Shree K K
- Jeniliya B

<p align="center">
  <img src="assets/detcap_banner.png" width="900"/>
</p>

<p align="center">
  <b>AI-Powered Network Reconnaissance & Security Analysis Tool</b><br/>
  <i>Like Nmap — but with an AI brain.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.1-00d4ff?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/AI-Ollama-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

---

## What is DETCAP?

**DETCAP** is an AI-powered network scanning and security analysis tool. It combines traditional port scanning (like Nmap) with AI-driven analysis powered by a local **Ollama** LLM to give you not just raw scan data, but intelligent security insights, CVE mappings, and actionable defense recommendations — all in a single tool.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **TCP Port Scanning** | Multi-threaded connect scan across configurable port ranges |
| 🥷 **SYN Stealth Scan** | Raw packet SYN scan (Scapy-powered, threaded) |
| 🧠 **OS Fingerprinting** | TTL + TCP window-based OS detection with confidence score |
| 🛰️ **Service Detection** | Banner grabbing and service/version identification |
| ⚠️ **CVE Mapping** | Automatic vulnerability lookup against local CVE database |
| 🤖 **AI Analysis** | Ollama LLM explains findings and suggests remediation |
| 📄 **HTML Report** | Styled, professional security report saved locally |
| 📦 **JSON Export** | Machine-readable output for integrations (`--json` flag) |
| ⚡ **CLI + Interactive** | Full `argparse` CLI for scripting, or guided interactive mode |

---

## Installation

```bash
git clone https://github.com/Darshan0412-k/detcap.git
cd detcap
pip install -r requirements.txt
```

### Prerequisites

- Python 3.8+
- [Ollama](https://ollama.ai) installed and running locally (for AI analysis)
- Administrator/root privileges for stealth (SYN) scan mode

Pull a model for AI analysis:
```bash
ollama pull llama3
```

---

## Usage

### Interactive Mode
```bash
python detcap.py
```

### CLI Mode
```bash
# Basic scan
python detcap.py -t 192.168.1.1

# Full scan with stealth mode and JSON export
python detcap.py -t 192.168.1.1 -p full -m stealth --json

# Fast scan, skip AI analysis
python detcap.py -t 192.168.1.1 -p fast --no-ai
```

### CLI Arguments

| Argument | Short | Description | Default |
|---|---|---|---|
| `--target` | `-t` | Target IP or hostname | *(prompted)* |
| `--profile` | `-p` | `fast` / `balanced` / `full` | `balanced` |
| `--mode` | `-m` | `normal` / `stealth` | `normal` |
| `--json` | | Also export JSON report | `False` |
| `--no-ai` | | Skip AI analysis | `False` |

---

## Scan Profiles

| Profile | Port Range | Threads | Timeout |
|---|---|---|---|
| `fast` | 1–200 | 100 | 1s |
| `balanced` | 1–1024 | 80 | 2s |
| `full` | 1–65535 | 120 | 2s |

---

## Scan Modes

- **normal** — Standard TCP connect scan using Python sockets (no root required)
- **stealth** — Raw SYN packet scan using Scapy (requires root/admin). Faster, less detectable, uses threading for speed

---

## AI Analysis (Ollama)

DETCAP uses a locally-running [Ollama](https://ollama.ai) instance for all AI analysis. **No data leaves your machine.** The AI model receives the scan results and generates a natural-language security report including risk assessment, exploitation context, and remediation steps.

Supported models: `llama3`, `mistral`, `gemma3`, or any Ollama-compatible model.

Configure your preferred model in `analysis/ai_explainer.py`:
```python
MODEL = "llama3"  # Change to your preferred Ollama model
```

---

## Output

### HTML Report
A styled dark-theme report is saved automatically to `reports/`:
```
reports/detcap_192_168_1_1_20250501_143022.html
```

### JSON Export (with `--json`)
```json
{
  "meta": { "version": "1.0.1", "target": "...", "timestamp": "..." },
  "os": { "os": "Linux", "confidence": 80 },
  "services": [ { "port": 22, "service": "SSH", "version": "OpenSSH 8.9" } ],
  "cves": [ { "cve": "CVE-2023-XXXX", "severity": "HIGH", "description": "..." } ],
  "attack_insights": [ ... ],
  "ai_report": "..."
}
```

---

## Project Structure

```
detcap/
├── detcap.py             # Main entry point
├── stealth_scan.py       # SYN stealth scanner (threaded)
├── report_generator.py   # HTML report engine
├── requirements.txt
├── core/
│   ├── scanner.py        # TCP connect scanner
│   └── service_detector.py
├── analysis/
│   ├── ai_explainer.py   # Ollama AI integration
│   ├── attack_advisor.py
│   ├── cve_mapper.py
│   └── fingerprint.py
├── data/                 # CVE and service databases
├── utils/
└── reports/              # Generated reports (auto-created)
```

---

## Changelog

### v1.0.1
- ✅ Fixed ANSI escape code stripping regex bug
- ✅ Added IP/hostname input validation
- ✅ Added full `argparse` CLI with `-t`, `-p`, `-m`, `--json`, `--no-ai`
- ✅ Stealth scanner now threaded (major speed improvement)
- ✅ Styled HTML reports with dark cyberpunk theme, stat cards, severity badges
- ✅ JSON export option
- ✅ Rich progress bar for stealth scan
- ✅ Severity color coding in terminal CVE table

### v1.0.0
- Initial release

---

## Disclaimer

> **DETCAP is for authorized security testing and educational purposes only.**
> Do not use this tool against systems you do not own or have explicit permission to test.
> The author is not responsible for any misuse.

---

## Author

**Darshan G** — [GitHub](https://github.com/Darshan0412-k)

## License

MIT — see [LICENSE](LICENSE)
