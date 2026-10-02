"""
REST API and Static Dashboard Server for FIM v2.0.
Exposes endpoints for baselines, verification checks, findings, reports download, Prometheus metrics, and UI dashboard.
"""

import http.server
import json
import socketserver
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

from ..config import ConfigManager
from ..core.baseline import BaselineManager
from ..core.comparator import IntegrityComparator
from ..reports.generator import ReportGenerator
from ..storage.db import DatabaseManager

class FIMHttpHandler(http.server.SimpleHTTPRequestHandler):
    """Native standard library HTTP handler with REST API, Reports, and Dashboard routing."""

    config: ConfigManager
    db: DatabaseManager
    baseline_mgr: BaselineManager
    comparator: IntegrityComparator
    web_dir: Path

    def _send_json(self, status: int, data: Any):
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file_download(self, filename: str, content_type: str, content: bytes):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _check_auth(self) -> bool:
        expected = self.config.get("api.bearer_token", "")
        if not expected:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip() == expected
        return False

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized. Invalid or missing Bearer token."})
            return

        if path == "/health" or path == "/api/health":
            self._send_json(200, {"status": "HEALTHY", "version": "2.0.0", "timestamp": time.time()})

        elif path == "/metrics" or path == "/api/metrics":
            baselines = self.db.list_baselines()
            total_b = len(baselines)
            metrics = [
                "# HELP fim_baselines_total Total number of configured baselines",
                "# TYPE fim_baselines_total gauge",
                f"fim_baselines_total {total_b}",
                "# HELP fim_up Status of FIM daemon",
                "# TYPE fim_up gauge",
                "fim_up 1"
            ]
            payload = "\n".join(metrics).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        elif path == "/baselines" or path == "/api/baselines":
            baselines = self.db.list_baselines()
            self._send_json(200, {"baselines": baselines})

        elif path == "/findings" or path == "/api/findings":
            run_id = int(query.get("run_id", [1])[0]) if query.get("run_id") else 1
            findings = self.db.get_findings_for_run(run_id)
            self._send_json(200, {"run_id": run_id, "findings": findings})

        elif path == "/audit" or path == "/api/audit":
            records = self.db.audit.get_recent_records(limit=50)
            valid, err, total = self.db.audit.verify_integrity()
            self._send_json(200, {
                "chain_valid": valid,
                "chain_error": err,
                "total_verified": total,
                "audit_records": records
            })

        # Direct Report Downloads
        elif path == "/api/reports/html" or path == "/reports/download/html":
            profile = query.get("profile", [""])[0]
            if not profile:
                baselines = self.db.list_baselines()
                profile = baselines[0]["name"] if baselines else "default"
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
                    tmp_p = tmp.name
                ReportGenerator.export_to_html(summary, tmp_p)
                content = Path(tmp_p).read_bytes()
                Path(tmp_p).unlink(missing_ok=True)
                self._send_file_download(f"fim_audit_{profile}.html", "text/html", content)
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate HTML report: {e}"})

        elif path == "/api/reports/json" or path == "/reports/download/json":
            profile = query.get("profile", [""])[0]
            if not profile:
                baselines = self.db.list_baselines()
                profile = baselines[0]["name"] if baselines else "default"
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                    tmp_p = tmp.name
                ReportGenerator.export_to_json(summary, tmp_p)
                content = Path(tmp_p).read_bytes()
                Path(tmp_p).unlink(missing_ok=True)
                self._send_file_download(f"fim_audit_{profile}.json", "application/json", content)
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate JSON report: {e}"})

        elif path == "/api/reports/csv" or path == "/reports/download/csv":
            profile = query.get("profile", [""])[0]
            if not profile:
                baselines = self.db.list_baselines()
                profile = baselines[0]["name"] if baselines else "default"
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
                    tmp_p = tmp.name
                ReportGenerator.export_to_csv(summary, tmp_p)
                content = Path(tmp_p).read_bytes()
                Path(tmp_p).unlink(missing_ok=True)
                self._send_file_download(f"fim_audit_{profile}.csv", "text/csv", content)
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate CSV report: {e}"})

        elif path == "/" or path == "/index.html":
            index_path = self.web_dir / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(200, {"message": "FIM v2.0 API Online."})

        elif path == "/dashboard.js":
            js_path = self.web_dir / "dashboard.js"
            if js_path.exists():
                content = js_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(404, {"error": "Not found"})

        elif path == "/styles.css":
            css_path = self.web_dir / "styles.css"
            if css_path.exists():
                content = css_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/css")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(404, {"error": "Not found"})

        else:
            self._send_json(404, {"error": f"Endpoint {path} not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized."})
            return

        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            body = json.loads(post_body)
        except Exception:
            body = {}

        if path == "/baselines" or path == "/api/baselines":
            name = body.get("name", "default")
            paths = body.get("paths", [])
            algo = body.get("algo", "sha256")
            if not paths:
                self._send_json(400, {"error": "Must provide 'paths' array"})
                return
            manifest = self.baseline_mgr.create_baseline(name=name, paths=paths, algo=algo)
            self._send_json(201, manifest.to_dict())

        elif path == "/checks" or path == "/api/checks":
            profile = body.get("profile", "")
            if not profile:
                baselines = self.db.list_baselines()
                profile = baselines[0]["name"] if baselines else "default"
            summary = self.comparator.check_baseline(profile_name=profile)
            self._send_json(200, summary.to_dict())

        elif path.startswith("/findings/") and path.endswith("/accept"):
            parts = path.strip("/").split("/")
            try:
                fid = int(parts[1])
                user = body.get("user", "api-user")
                ok = self.db.accept_finding(fid, user=user)
                self._send_json(200, {"success": ok, "finding_id": fid})
            except Exception as e:
                self._send_json(400, {"error": str(e)})

        else:
            self._send_json(404, {"error": f"Endpoint {path} not found"})


def run_server(host: str = "127.0.0.1", port: int = 8000, config: Optional[ConfigManager] = None):
    """Starts the standalone FIM API and Dashboard server."""
    cfg = config or ConfigManager()
    db = DatabaseManager(cfg.db_path)
    b_mgr = BaselineManager(cfg, db)
    comp = IntegrityComparator(cfg, db)
    web_dir = Path(__file__).resolve().parent.parent / "web"

    FIMHttpHandler.config = cfg
    FIMHttpHandler.db = db
    FIMHttpHandler.baseline_mgr = b_mgr
    FIMHttpHandler.comparator = comp
    FIMHttpHandler.web_dir = web_dir

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer((host, port), FIMHttpHandler) as httpd:
        print(f"\n=======================================================")
        print(f" 🛡️  FIM v2.0 REST API & Web Dashboard Running (Multi-threaded)")
        print(f" URL: http://{host}:{port}/")
        print(f" Download HTML Report : http://{host}:{port}/api/reports/html")
        print(f" Download CSV Report  : http://{host}:{port}/api/reports/csv")
        print(f" Download JSON Report : http://{host}:{port}/api/reports/json")
        print(f" Health Check         : http://{host}:{port}/health")
        print(f" Prometheus Metrics   : http://{host}:{port}/metrics")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.shutdown()
