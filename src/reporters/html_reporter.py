"""
HTML Reporter — Beautiful security report
"""

from pathlib import Path
from datetime import datetime


class HTMLReporter:

    def __init__(self, output_path: str = None):
        self.output_path = output_path or "secrets-report.html"

    def report(self, results: dict):
        html = self._generate_html(results)
        Path(self.output_path).write_text(html, encoding="utf-8")
        print(f"\n✅ HTML report saved to: {self.output_path}")

    def _generate_html(self, results: dict) -> str:
        findings = results.get("findings", [])
        total = results.get("total_found", 0)
        breakdown = results.get("severity_breakdown", {})
        scan_path = results.get("scan_path", ".")
        timestamp = results.get("timestamp", datetime.now().isoformat())

        findings_html = ""
        for f in findings:
            color = {"critical": "#ff4444", "high": "#ff8800",
                     "medium": "#ffcc00", "low": "#44bb44"}.get(f["severity"], "#888")
            findings_html += f"""
            <div class="finding">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <span class="severity" style="color:{color}">{f['severity'].upper()}</span>
                    <span class="rule-name">{f['rule_name']}</span>
                    <span class="category">{f['category']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>📁 File:</strong> <code>{f['file']}:{f['line']}</code></p>
                    <p><strong>🔍 Match:</strong> <code class="match">{f['match']}</code></p>
                    <p><strong>📝 Description:</strong> {f['description']}</p>
                    <p><strong>🔧 Fix:</strong> <span class="fix">{f['remediation']}</span></p>
                </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔐 Secrets Detector Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #e6edf3; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1b2a4a, #0d7377);
             padding: 40px; text-align: center; }}
  .header h1 {{ font-size: 2.5rem; margin-bottom: 8px; }}
  .header p {{ color: #7ba7c9; font-size: 1.1rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px; margin: 30px 0; }}
  .stat-card {{ background: #161b22; border-radius: 12px; padding: 20px;
               text-align: center; border: 1px solid #30363d; }}
  .stat-number {{ font-size: 2.5rem; font-weight: bold; }}
  .stat-label {{ color: #7d8590; font-size: 0.85rem; margin-top: 4px; }}
  .critical {{ color: #ff4444; }} .high {{ color: #ff8800; }}
  .medium {{ color: #ffcc00; }} .low {{ color: #44bb44; }}
  .finding {{ background: #161b22; border-radius: 8px; margin: 16px 0;
              border: 1px solid #30363d; overflow: hidden; }}
  .finding-header {{ padding: 12px 16px; background: #0d1117;
                     display: flex; align-items: center; gap: 12px; }}
  .severity {{ font-weight: bold; font-size: 0.8rem; padding: 3px 8px;
               border-radius: 4px; background: rgba(255,255,255,0.1); }}
  .rule-name {{ font-weight: 600; font-size: 1rem; }}
  .category {{ color: #7d8590; font-size: 0.85rem; margin-left: auto; }}
  .finding-body {{ padding: 16px; }}
  .finding-body p {{ margin: 8px 0; }}
  code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px;
          font-family: monospace; font-size: 0.9rem; }}
  .match {{ color: #ff6b6b; }}
  .fix {{ color: #44bb44; }}
  .section-title {{ font-size: 1.3rem; font-weight: bold; margin: 30px 0 16px;
                   color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  .meta {{ background: #161b22; border-radius: 8px; padding: 16px;
           border: 1px solid #30363d; margin-bottom: 24px; color: #7d8590; }}
  .clean {{ text-align: center; padding: 60px; color: #44bb44; font-size: 1.5rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Secrets Detector Report</h1>
  <p>Security scan completed — {timestamp[:19].replace('T', ' ')}</p>
</div>
<div class="container">
  <div class="meta">
    📁 Scanned: <strong>{scan_path}</strong> &nbsp;|&nbsp;
    📄 Files: <strong>{results.get('scanned_files', 0)}</strong> &nbsp;|&nbsp;
    🔍 Findings: <strong>{total}</strong>
  </div>
  <div class="stats">
    <div class="stat-card">
      <div class="stat-number" style="color:#e6edf3">{total}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-number critical">{breakdown.get('critical', 0)}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-number high">{breakdown.get('high', 0)}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card">
      <div class="stat-number medium">{breakdown.get('medium', 0)}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="stat-number low">{breakdown.get('low', 0)}</div>
      <div class="stat-label">Low</div>
    </div>
  </div>
  {"<div class='section-title'>🚨 Findings</div>" + findings_html if findings else "<div class='clean'>✅ No secrets detected! Your codebase is clean.</div>"}
</div>
</body>
</html>"""
