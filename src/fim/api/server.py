"""
REST API and Static Dashboard Server for FIM v2.1.
Exposes endpoints for baselines, verification checks, findings, reports download, Prometheus metrics, and UI dashboard.
Enforces loopback interface bind security, CORS origin allowlist, and header-only API/Dashboard authentication.
"""

import http.server
import json
import logging
import os
import secrets
import socketserver
import stat
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from ..config import ConfigManager
from ..core.baseline import BaselineManager
from ..core.comparator import IntegrityComparator
from ..reports.generator import ReportGenerator
from ..storage.db import DatabaseManager

logger = logging.getLogger("fim.api")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class FIMHttpHandler(http.server.SimpleHTTPRequestHandler):
    """Native standard library HTTP handler with REST API, Reports, and Dashboard routing."""

    config: ConfigManager
    db: DatabaseManager
    baseline_mgr: BaselineManager
    comparator: IntegrityComparator
    web_dir: Path
    api_token: str

    def _get_cors_origin(self) -> str:
        """Determines if the requesting Origin is explicitly permitted by config allowlist."""
        request_origin = self.headers.get("Origin", "")
        if not request_origin:
            return ""
        allowed = self.config.get(
            "api.allowed_origins",
            [
                "http://localhost:8000",
                "http://127.0.0.1:8000",
                "http://localhost",
                "http://127.0.0.1",
            ],
        )
        if request_origin in allowed or "*" in allowed:
            return request_origin
        return ""

    def _send_json(self, status: int, data: Any, include_cors: bool = True):
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if include_cors:
            origin = self._get_cors_origin()
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header(
                    "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key"
                )
        self.end_headers()
        self.wfile.write(payload)

    def _send_file_download(self, filename: str, content_type: str, content: bytes):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        origin = self._get_cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(content)

    def _check_auth(self) -> bool:
        """
        Validates authentication using HTTP headers only (Authorization: Bearer or X-API-Key).
        URL query parameter tokens are explicitly rejected to prevent leakage in server access logs and Referer headers.
        """
        if not self.api_token:
            return True

        # Check Authorization header: Bearer <token>
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:].strip(), self.api_token):
            return True

        # Check X-API-Key header
        api_key = self.headers.get("X-API-Key", "")
        if secrets.compare_digest(api_key.strip(), self.api_token):
            return True

        return False

    def do_OPTIONS(self):
        self.send_response(200)
        origin = self._get_cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key"
            )
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Allow unauthenticated health check without CORS headers
        if path == "/health" or path == "/api/health":
            self._send_json(
                200,
                {"status": "HEALTHY", "version": "2.3.0", "timestamp": time.time()},
                include_cors=False,
            )
            return

        # Static dashboard assets (allow loading UI HTML/CSS/JS; UI authenticates API requests via headers)
        if path in ["/", "/index.html", "/styles.css", "/dashboard.js"]:
            filename = "index.html" if path in ["/", "/index.html"] else path.lstrip("/")
            static_file = self.web_dir / filename
            if static_file.exists():
                content = static_file.read_bytes()
                mime = (
                    "text/html; charset=utf-8"
                    if filename.endswith(".html")
                    else (
                        "text/css; charset=utf-8"
                        if filename.endswith(".css")
                        else "application/javascript; charset=utf-8"
                    )
                )
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # All API endpoints require header authentication
        if not self._check_auth():
            self._send_json(
                401,
                {
                    "error": "Unauthorized. Provide Authorization: Bearer <token> or X-API-Key: <token> HTTP header."
                },
            )
            return

        if path == "/metrics" or path == "/api/metrics":
            baselines = self.db.list_baselines()
            total_b = len(baselines)
            metrics = [
                "# HELP fim_baselines_total Total number of configured baselines",
                "# TYPE fim_baselines_total gauge",
                f"fim_baselines_total {total_b}",
                "# HELP fim_up Status of FIM daemon",
                "# TYPE fim_up gauge",
                "fim_up 1",
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
            raw_limit = query.get("limit", ["100"])[0]
            try:
                limit = int(raw_limit)
                if limit < 0:
                    raise ValueError("limit must be non-negative")
            except (ValueError, TypeError):
                self._send_json(
                    400,
                    {
                        "error": f"Invalid 'limit' query parameter: '{raw_limit}'. Must be a non-negative integer."
                    },
                )
                return
            findings = self.db.get_unresolved_findings(limit=limit)
            self._send_json(200, {"findings": findings})

        elif path == "/audit" or path == "/api/audit":
            raw_limit = query.get("limit", ["50"])[0]
            try:
                limit = int(raw_limit)
                if limit < 0:
                    raise ValueError("limit must be non-negative")
            except (ValueError, TypeError):
                self._send_json(
                    400,
                    {
                        "error": f"Invalid 'limit' query parameter: '{raw_limit}'. Must be a non-negative integer."
                    },
                )
                return
            valid, msg, count = self.db.audit.verify_integrity()
            events = self.db.audit.get_events(limit=limit)
            self._send_json(
                200, {"chain_valid": valid, "message": msg, "total_events": count, "events": events}
            )

        elif path == "/api/reports/html":
            profile = query.get("profile", ["default"])[0]
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                html_str = ReportGenerator.export_to_html(summary)
                self._send_file_download(
                    f"fim_report_{profile}.html", "text/html", html_str.encode("utf-8")
                )
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate HTML report: {e}"})

        elif path == "/api/reports/json":
            profile = query.get("profile", ["default"])[0]
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                json_str = ReportGenerator.export_to_json(summary)
                self._send_file_download(
                    f"fim_report_{profile}.json", "application/json", json_str.encode("utf-8")
                )
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate JSON report: {e}"})

        elif path == "/api/reports/csv":
            profile = query.get("profile", ["default"])[0]
            try:
                summary = self.comparator.check_baseline(profile_name=profile)
                csv_str = ReportGenerator.export_to_csv(summary)
                self._send_file_download(
                    f"fim_report_{profile}.csv", "text/csv", csv_str.encode("utf-8")
                )
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate CSV report: {e}"})

        else:
            self._send_json(404, {"error": f"Endpoint {path} not found"})

    MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB limit

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._check_auth():
            self._send_json(
                401,
                {
                    "error": "Unauthorized. Provide Authorization: Bearer <token> or X-API-Key: <token>."
                },
            )
            return

        raw_len = self.headers.get("Content-Length", "0")
        try:
            content_len = int(raw_len)
            if content_len < 0:
                raise ValueError("Negative Content-Length")
        except (ValueError, TypeError):
            self._send_json(400, {"error": f"Invalid Content-Length header: '{raw_len}'"})
            return

        if content_len > self.MAX_REQUEST_BODY_BYTES:
            self._send_json(
                413,
                {
                    "error": f"Request body too large ({content_len} bytes). Maximum allowed is {self.MAX_REQUEST_BODY_BYTES} bytes."
                },
            )
            return

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


def resolve_api_token(cfg: ConfigManager) -> str:
    """Retrieves API bearer token from config, env, or ~/.fim/.api_token with 0600 permissions."""
    token = cfg.get("api.bearer_token") or os.getenv("FIM_API_TOKEN")
    if token and str(token).strip():
        return str(token).strip()

    token_file = cfg.db_path.parent / ".api_token"
    try:
        if token_file.exists():
            stored = token_file.read_text(encoding="utf-8").strip()
            if stored:
                return stored

        generated = secrets.token_hex(32)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(generated, encoding="utf-8")
        if os.name != "nt":
            os.chmod(token_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logger.error(f"Failed to access or persist API token to '{token_file}': {e}")
        raise RuntimeError(
            f"Failed to read or persist API token at '{token_file}': {e}. "
            f"Please ensure write permissions to '{token_file.parent}' or configure an explicit token "
            f"via the 'FIM_API_TOKEN' environment variable or 'api.bearer_token' in config."
        ) from e


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    config: Optional[ConfigManager] = None,
    allow_remote: bool = False,
):
    """
    Starts the standalone FIM API and Dashboard server.
    Refuses non-loopback bind by default unless allow_remote is explicitly set.
    Refuses wildcard CORS on non-loopback interfaces.
    """
    cfg = config or ConfigManager()
    allowed_origins = cfg.get(
        "api.allowed_origins",
        ["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost", "http://127.0.0.1"],
    )

    # Bind security check
    if host not in LOOPBACK_HOSTS and not allow_remote and not cfg.get("api.allow_remote", False):
        raise PermissionError(
            f"[SECURITY REFUSAL] Refusing to bind to non-loopback interface '{host}' by default. "
            f"Exposing the FIM management API externally requires explicit '--allow-remote' flag and configured authentication."
        )

    if host not in LOOPBACK_HOSTS and "*" in allowed_origins:
        raise PermissionError("Wildcard CORS ('*') is not allowed on non-loopback interfaces.")

    db = DatabaseManager(cfg.db_path)
    b_mgr = BaselineManager(cfg, db)
    comp = IntegrityComparator(cfg, db)
    web_dir = Path(__file__).resolve().parent.parent / "web"
    api_token = resolve_api_token(cfg)

    if len(api_token) < 32:
        logger.warning(
            "API token is shorter than 32 characters — consider generating a stronger token."
        )

    FIMHttpHandler.config = cfg
    FIMHttpHandler.db = db
    FIMHttpHandler.baseline_mgr = b_mgr
    FIMHttpHandler.comparator = comp
    FIMHttpHandler.web_dir = web_dir
    FIMHttpHandler.api_token = api_token

    token_file = cfg.db_path.parent / ".api_token"
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer((host, port), FIMHttpHandler) as httpd:
        print("\n=======================================================")
        print(" 🛡️  FIM v2.3 REST API & Web Dashboard Running (Multi-threaded)")
        print(f" URL: http://{host}:{port}/")
        print(f" Auth Token File: {token_file}")
        print(" (Supply via 'Authorization: Bearer <token>' or 'X-API-Key: <token>')")
        print(f" Health Check: http://{host}:{port}/health")
        print(
            f" Prometheus Metrics: curl -H \"Authorization: Bearer $(cat '{token_file}')\" http://{host}:{port}/metrics"
        )
        print("=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.shutdown()
