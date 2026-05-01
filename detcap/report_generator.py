"""
DETCAP v1.0.1 — HTML Report Generator
Generates a styled, professional security report.
"""

from __future__ import annotations
from html import escape


def _severity_class(severity: str) -> str:
    return {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
    }.get(severity.upper(), "sev-info")


def _risk_badge(severity: str) -> str:
    cls = _severity_class(severity)
    return f'<span class="badge {cls}">{escape(severity.upper())}</span>'


def generate_html_report(
    path: str,
    target: str,
    profile_name: str,
    mode: str,
    os_info: dict,
    services: list,
    flat_cves: list,
    suggestions: list,
    ai_report: str,
    timestamp: str,
    version: str,
) -> None:

    # ── Summary stats ──────────────────────────────────────────────────────
    critical = sum(1 for c in flat_cves if c["severity"].upper() == "CRITICAL")
    high = sum(1 for c in flat_cves if c["severity"].upper() == "HIGH")
    medium = sum(1 for c in flat_cves if c["severity"].upper() == "MEDIUM")
    low = sum(1 for c in flat_cves if c["severity"].upper() == "LOW")

    # ── Services rows ──────────────────────────────────────────────────────
    svc_rows = ""
    for s in services:
        svc_rows += f"""
        <tr>
          <td><span class="port-badge">{escape(str(s['port']))}</span></td>
          <td>{escape(s.get('service', '—'))}</td>
          <td class="mono">{escape((s.get('version') or '—')[:40])}</td>
        </tr>"""

    # ── CVE rows ───────────────────────────────────────────────────────────
    cve_rows = ""
    for c in flat_cves:
        cve_rows += f"""
        <tr>
          <td class="mono cve-id">{escape(c['cve'])}</td>
          <td>{_risk_badge(c['severity'])}</td>
          <td>{escape(c.get('description', '—'))}</td>
        </tr>"""

    if not cve_rows:
        cve_rows = '<tr><td colspan="3" class="empty-row">✅ No CVEs matched.</td></tr>'

    # ── Attack insight rows ────────────────────────────────────────────────
    insight_rows = ""
    for s in suggestions:
        insight_rows += f"""
        <tr>
          <td>{escape(s.get('service', '—'))}</td>
          <td class="risk-text">{escape(s.get('risk', '—'))}</td>
          <td class="defense-text">{escape(s.get('defense', '—'))}</td>
        </tr>"""

    if not insight_rows:
        insight_rows = '<tr><td colspan="3" class="empty-row">No insights generated.</td></tr>'

    # ── AI report block ────────────────────────────────────────────────────
    ai_block = ""
    if ai_report.strip():
        ai_block = f"""
      <section class="section">
        <h2 class="section-title"><span class="icon">🤖</span> AI Security Analysis <span class="model-tag">Ollama</span></h2>
        <div class="ai-report">{escape(ai_report)}</div>
      </section>"""

    # ── Friendly timestamp ─────────────────────────────────────────────────
    from datetime import datetime
    try:
        dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
        friendly_ts = dt.strftime("%B %d, %Y at %H:%M:%S")
    except Exception:
        friendly_ts = timestamp

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DETCAP Report — {escape(target)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Chakra+Petch:wght@400;600;700&display=swap" rel="stylesheet" />
  <style>
    /* ─── Reset & base ─────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:        #060a0f;
      --bg2:       #0c1420;
      --bg3:       #111c2d;
      --border:    #1a3050;
      --accent:    #00d4ff;
      --accent2:   #00ff88;
      --accent3:   #ff6b35;
      --text:      #c8d8e8;
      --text-dim:  #5a7a9a;
      --critical:  #ff2d55;
      --high:      #ff6b35;
      --medium:    #ffd60a;
      --low:       #30d158;
      --font-ui:   'Chakra Petch', monospace;
      --font-mono: 'Share Tech Mono', monospace;
      --glow:      0 0 20px rgba(0, 212, 255, 0.15);
    }}

    html {{ scroll-behavior: smooth; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-ui);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      background-image:
        radial-gradient(ellipse at 20% 0%, rgba(0,212,255,0.04) 0%, transparent 60%),
        radial-gradient(ellipse at 80% 100%, rgba(0,255,136,0.03) 0%, transparent 60%),
        repeating-linear-gradient(
          0deg, transparent,
          transparent 39px,
          rgba(0,212,255,0.03) 39px,
          rgba(0,212,255,0.03) 40px
        );
    }}

    /* ─── Layout ────────────────────────────────────────── */
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 40px 24px 80px;
    }}

    /* ─── Header ─────────────────────────────────────────── */
    .header {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 32px;
      margin-bottom: 40px;
      animation: fadeDown 0.5s ease both;
    }}

    .logo {{
      font-size: 42px;
      font-weight: 700;
      letter-spacing: 6px;
      color: var(--accent);
      text-shadow: 0 0 30px rgba(0,212,255,0.5), 0 0 60px rgba(0,212,255,0.2);
      line-height: 1;
    }}

    .logo .version {{
      font-size: 13px;
      color: var(--text-dim);
      letter-spacing: 2px;
      margin-top: 4px;
    }}

    .meta {{
      text-align: right;
      font-family: var(--font-mono);
      color: var(--text-dim);
      font-size: 12px;
      line-height: 2;
    }}

    .meta .target-val {{
      color: var(--accent2);
      font-size: 15px;
      font-weight: 600;
    }}

    /* ─── Stats row ──────────────────────────────────────── */
    .stats-row {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
      animation: fadeUp 0.5s ease 0.1s both;
    }}

    .stat-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px 16px;
      text-align: center;
      transition: border-color 0.2s, box-shadow 0.2s;
      position: relative;
      overflow: hidden;
    }}

    .stat-card::before {{
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(135deg, rgba(0,212,255,0.03), transparent);
      pointer-events: none;
    }}

    .stat-card:hover {{
      border-color: var(--accent);
      box-shadow: var(--glow);
    }}

    .stat-number {{
      font-size: 36px;
      font-weight: 700;
      font-family: var(--font-mono);
      line-height: 1;
      margin-bottom: 6px;
    }}

    .stat-label {{
      font-size: 11px;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--text-dim);
    }}

    .stat-card.ports .stat-number  {{ color: var(--accent); }}
    .stat-card.cves .stat-number   {{ color: var(--high); }}
    .stat-card.crit .stat-number   {{ color: var(--critical); }}
    .stat-card.os .stat-number     {{ color: var(--accent2); font-size: 18px; padding-top: 8px; }}

    /* ─── Sections ───────────────────────────────────────── */
    .section {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 28px;
      margin-bottom: 28px;
      animation: fadeUp 0.5s ease both;
      box-shadow: 0 4px 24px rgba(0,0,0,0.4);
    }}

    .section-title {{
      font-size: 16px;
      font-weight: 600;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
    }}

    .icon {{ font-style: normal; }}

    .model-tag {{
      font-size: 10px;
      background: rgba(0,212,255,0.1);
      border: 1px solid rgba(0,212,255,0.3);
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 20px;
      letter-spacing: 1px;
      margin-left: auto;
    }}

    /* ─── Tables ─────────────────────────────────────────── */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}

    th {{
      font-family: var(--font-ui);
      font-size: 10px;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--text-dim);
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
    }}

    td {{
      padding: 10px 12px;
      border-bottom: 1px solid rgba(26,48,80,0.5);
      vertical-align: top;
    }}

    tr:last-child td {{ border-bottom: none; }}

    tr:hover td {{
      background: rgba(0,212,255,0.03);
    }}

    .mono {{ font-family: var(--font-mono); font-size: 12px; }}

    .port-badge {{
      display: inline-block;
      background: rgba(0,212,255,0.1);
      border: 1px solid rgba(0,212,255,0.3);
      color: var(--accent);
      font-family: var(--font-mono);
      font-size: 12px;
      padding: 2px 8px;
      border-radius: 4px;
    }}

    .cve-id {{
      color: var(--critical);
      font-size: 12px;
    }}

    .empty-row {{
      text-align: center;
      color: var(--text-dim);
      padding: 24px !important;
      font-style: italic;
    }}

    /* ─── Severity badges ────────────────────────────────── */
    .badge {{
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 1.5px;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }}

    .sev-critical {{ background: rgba(255,45,85,0.2);  color: var(--critical); border: 1px solid rgba(255,45,85,0.4); }}
    .sev-high     {{ background: rgba(255,107,53,0.2); color: var(--high);     border: 1px solid rgba(255,107,53,0.4); }}
    .sev-medium   {{ background: rgba(255,214,10,0.15);color: var(--medium);   border: 1px solid rgba(255,214,10,0.3); }}
    .sev-low      {{ background: rgba(48,209,88,0.15); color: var(--low);      border: 1px solid rgba(48,209,88,0.3); }}
    .sev-info     {{ background: rgba(100,100,100,0.2);color: #888;            border: 1px solid #444; }}

    /* ─── Risk / Defense text ────────────────────────────── */
    .risk-text    {{ color: var(--high); font-size: 13px; }}
    .defense-text {{ color: var(--accent2); font-size: 13px; }}

    /* ─── AI block ───────────────────────────────────────── */
    .ai-report {{
      font-family: var(--font-mono);
      font-size: 12.5px;
      line-height: 1.8;
      color: var(--text);
      background: var(--bg3);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      border-radius: 6px;
      padding: 20px 24px;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    /* ─── OS info bar ────────────────────────────────────── */
    .os-bar {{
      display: flex;
      align-items: center;
      gap: 16px;
      background: var(--bg3);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent2);
      border-radius: 6px;
      padding: 14px 20px;
      font-family: var(--font-mono);
    }}

    .os-bar .os-name {{ color: var(--accent2); font-size: 16px; font-weight: 600; }}
    .os-bar .os-conf {{ color: var(--text-dim); font-size: 12px; margin-left: auto; }}

    /* ─── Scan meta pills ────────────────────────────────── */
    .scan-meta {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }}

    .pill {{
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 4px 14px;
      font-size: 11px;
      letter-spacing: 1px;
      color: var(--text-dim);
    }}

    .pill span {{ color: var(--text); margin-left: 4px; }}

    /* ─── Footer ─────────────────────────────────────────── */
    .footer {{
      text-align: center;
      margin-top: 48px;
      color: var(--text-dim);
      font-size: 11px;
      letter-spacing: 1px;
      font-family: var(--font-mono);
      border-top: 1px solid var(--border);
      padding-top: 24px;
    }}

    .footer .disclaimer {{
      margin-top: 8px;
      font-size: 10px;
      opacity: 0.6;
    }}

    /* ─── Scanline overlay ───────────────────────────────── */
    body::after {{
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.07) 2px,
        rgba(0,0,0,0.07) 4px
      );
      pointer-events: none;
      z-index: 9999;
    }}

    /* ─── Animations ─────────────────────────────────────── */
    @keyframes fadeDown {{
      from {{ opacity: 0; transform: translateY(-16px); }}
      to   {{ opacity: 1; transform: translateY(0); }}
    }}

    @keyframes fadeUp {{
      from {{ opacity: 0; transform: translateY(16px); }}
      to   {{ opacity: 1; transform: translateY(0); }}
    }}

    .section:nth-child(1) {{ animation-delay: 0.10s; }}
    .section:nth-child(2) {{ animation-delay: 0.18s; }}
    .section:nth-child(3) {{ animation-delay: 0.26s; }}
    .section:nth-child(4) {{ animation-delay: 0.34s; }}
    .section:nth-child(5) {{ animation-delay: 0.42s; }}

    /* ─── Print ──────────────────────────────────────────── */
    @media print {{
      body {{ background: white; color: black; }}
      body::after {{ display: none; }}
      .section {{ box-shadow: none; border-color: #ccc; }}
    }}
  </style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header class="header">
    <div>
      <div class="logo">DETCAP</div>
      <div class="logo version">v{escape(version)} · Security Report</div>
    </div>
    <div class="meta">
      <div>Generated: {escape(friendly_ts)}</div>
      <div>Target: <span class="target-val">{escape(target)}</span></div>
      <div>Profile: {escape(profile_name.upper())} · Mode: {escape(mode.upper())}</div>
    </div>
  </header>

  <!-- Stats row -->
  <div class="stats-row">
    <div class="stat-card ports">
      <div class="stat-number">{len(services)}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card cves">
      <div class="stat-number">{len(flat_cves)}</div>
      <div class="stat-label">CVEs Found</div>
    </div>
    <div class="stat-card crit">
      <div class="stat-number">{critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card" style="--n-color:var(--high)">
      <div class="stat-number" style="color:var(--high)">{high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card" style="--n-color:var(--medium)">
      <div class="stat-number" style="color:var(--medium)">{medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card os">
      <div class="stat-number">{escape(os_info.get('os', 'Unknown'))}</div>
      <div class="stat-label">OS · {escape(str(os_info.get('confidence', '?')))}% conf.</div>
    </div>
  </div>

  <!-- Services -->
  <section class="section">
    <h2 class="section-title"><span class="icon">🛰️</span> Services Detected</h2>
    <table>
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>Version / Banner</th>
        </tr>
      </thead>
      <tbody>
        {svc_rows if svc_rows else '<tr><td colspan="3" class="empty-row">No open ports found.</td></tr>'}
      </tbody>
    </table>
  </section>

  <!-- CVEs -->
  <section class="section">
    <h2 class="section-title"><span class="icon">⚠️</span> Vulnerabilities (CVEs)</h2>
    <table>
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Severity</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>{cve_rows}</tbody>
    </table>
  </section>

  <!-- Attack Insights -->
  <section class="section">
    <h2 class="section-title"><span class="icon">⚔️</span> Attack Insights</h2>
    <table>
      <thead>
        <tr>
          <th>Service</th>
          <th>Risk</th>
          <th>Defense Recommendation</th>
        </tr>
      </thead>
      <tbody>{insight_rows}</tbody>
    </table>
  </section>

  <!-- AI Analysis -->
  {ai_block}

  <!-- Footer -->
  <footer class="footer">
    DETCAP v{escape(version)} · Built by Darshan G · MIT License
    <div class="disclaimer">
      ⚠️ For authorized security testing and educational use only. Do not use against systems you don't own.
    </div>
  </footer>

</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
