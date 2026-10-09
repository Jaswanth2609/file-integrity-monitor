"""
Multi-Format Report Generator for FIM v2.1.
Exports verification and scan results to JSON, CSV, formatted TXT, and interactive HTML.
Supports both direct string returns (for HTTP API endpoints) and file persistence.
"""

import csv
import io
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

class ReportGenerator:
    """Generates structured audit reports in multiple formats."""

    @staticmethod
    def _normalize_data(data: Any) -> Dict[str, Any]:
        if hasattr(data, "to_dict"):
            return data.to_dict()
        if isinstance(data, dict):
            return data
        return {"data": str(data)}

    @staticmethod
    def export_to_json(data: Any, output_path: Optional[Union[str, Path]] = None) -> str:
        """Exports report to formatted JSON following the FIM schema."""
        norm = ReportGenerator._normalize_data(data)
        wrapped = {
            "schema_version": "2.1.0",
            "generator": "File Integrity Monitor (FIM) v2.1",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "report_data": norm
        }
        content = json.dumps(wrapped, indent=2)

        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
            return str(out)

        return content

    @staticmethod
    def export_to_csv(data: Any, output_path: Optional[Union[str, Path]] = None) -> str:
        """Exports findings or scan results to standard CSV."""
        norm = ReportGenerator._normalize_data(data)
        findings = norm.get("findings", [])
        if not findings and isinstance(norm.get("files"), list):
            findings = norm.get("files", [])

        fieldnames = ["path", "change_type", "severity", "description", "old_hash", "new_hash", "attack_id"]

        output_io = io.StringIO()
        writer = csv.DictWriter(output_io, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in findings:
            if isinstance(row, dict):
                writer.writerow(row)

        content = output_io.getvalue()

        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
            return str(out)

        return content

    @staticmethod
    def export_to_txt(data: Any, output_path: Optional[Union[str, Path]] = None) -> str:
        """Exports human-readable ASCII/Text audit report."""
        norm = ReportGenerator._normalize_data(data)
        findings = norm.get("findings", [])

        lines = [
            "=" * 78,
            " FILE INTEGRITY MONITOR (FIM) v2.1 - AUDIT REPORT",
            "=" * 78,
            f" Report Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f" Profile / Target : {norm.get('profile', norm.get('target', 'Manual Scan'))}",
            f" Changes Detected : {len(findings)}",
            f" Exit Code        : {norm.get('exit_code', 0)}",
            "-" * 78,
            " FINDINGS SUMMARY",
            "-" * 78,
        ]

        if not findings:
            lines.append(" [✓] No unauthorized changes or integrity violations detected.")
        else:
            for idx, f in enumerate(findings, 1):
                lines.append(f" [{idx}] [{f.get('severity', 'INFO')}] {f.get('change_type', 'EVENT')}: {f.get('path')}")
                lines.append(f"     Details   : {f.get('description', 'N/A')}")
                if f.get('attack_id'):
                    lines.append(f"     MITRE ID  : {f.get('attack_id')}")
                if f.get('old_hash'):
                    lines.append(f"     Old Hash  : {f.get('old_hash')}")
                if f.get('new_hash'):
                    lines.append(f"     New Hash  : {f.get('new_hash')}")
                lines.append("")

        lines.append("=" * 78)
        content = "\n".join(lines)

        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
            return str(out)

        return content

    @staticmethod
    def export_to_html(data: Any, output_path: Optional[Union[str, Path]] = None) -> str:
        """Exports a modern, self-contained HTML report with responsive dark styling and filters."""
        norm = ReportGenerator._normalize_data(data)
        findings = norm.get("findings", [])
        profile = norm.get("profile", "Default")
        exported_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") in ("LOW", "INFO"))

        rows_html = []
        for f in findings:
            sev = f.get("severity", "INFO")
            badge_class = f"badge-{sev.lower()}"
            rows_html.append(f"""
                <tr>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td><strong>{f.get('change_type', 'EVENT')}</strong></td>
                    <td class="code-path">{f.get('path', '')}</td>
                    <td>{f.get('description', '')}</td>
                    <td><code>{f.get('attack_id') or '—'}</code></td>
                    <td><code class="hash-str">{f.get('new_hash') or f.get('old_hash') or '—'}</code></td>
                </tr>
            """)

        table_body = "".join(rows_html) if rows_html else '<tr><td colspan="6" style="text-align:center; padding: 2rem;">No file changes detected. Integrity verified.</td></tr>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FIM v2.1 - Security Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #10b981;
            --border: #334155;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .card h4 {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }}
        .card .value {{ font-size: 1.8rem; font-weight: 700; }}
        .text-crit {{ color: var(--critical); }}
        .text-high {{ color: var(--high); }}
        .text-med {{ color: var(--medium); }}
        .text-low {{ color: var(--low); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        th, td {{
            padding: 0.85rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}
        th {{ background-color: rgba(0, 0, 0, 0.2); color: var(--text-muted); font-weight: 600; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .badge-high {{ background-color: rgba(249, 115, 22, 0.2); color: var(--high); }}
        .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: var(--medium); }}
        .badge-low {{ background-color: rgba(16, 185, 129, 0.2); color: var(--low); }}
        .badge-info {{ background-color: rgba(56, 189, 248, 0.2); color: var(--accent); }}
        .code-path {{ font-family: monospace; color: #cbd5e1; word-break: break-all; }}
        .hash-str {{ font-family: monospace; font-size: 0.8rem; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ File Integrity Monitor Report</h1>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">
                    Profile: <strong>{profile}</strong> | Generated: {exported_at}
                </p>
            </div>
            <div>
                <span class="badge {'badge-critical' if len(findings) > 0 else 'badge-low'}" style="font-size: 1rem; padding: 0.5rem 1rem;">
                    {'CHANGES DETECTED' if len(findings) > 0 else 'SYSTEM VERIFIED'}
                </span>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="card">
                <h4>Total Changes</h4>
                <div class="value">{len(findings)}</div>
            </div>
            <div class="card">
                <h4>Critical Findings</h4>
                <div class="value text-crit">{crit_count}</div>
            </div>
            <div class="card">
                <h4>High Findings</h4>
                <div class="value text-high">{high_count}</div>
            </div>
            <div class="card">
                <h4>Medium / Low</h4>
                <div class="value text-med">{med_count + low_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Change Type</th>
                    <th>Path</th>
                    <th>Description</th>
                    <th>MITRE ATT&CK</th>
                    <th>Hash</th>
                </tr>
            </thead>
            <tbody>
                {table_body}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(html_content, encoding="utf-8")
            return str(out)

        return html_content
