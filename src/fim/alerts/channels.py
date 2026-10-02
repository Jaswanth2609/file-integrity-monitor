"""
Alert Notification Channels for FIM v2.0.
Supports Console, Log File, SMTP Email, Slack Webhook, Telegram Bot, Webhooks, and Syslog.
"""

import json
import logging
import smtplib
import socket
import sys
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, Optional

class ConsoleAlertChannel:
    def send(self, alert_data: Dict[str, Any]) -> bool:
        sev = alert_data.get("severity", "INFO")
        path = alert_data.get("path", "")
        desc = alert_data.get("description", "")
        # ANSI colors
        color = "\033[91m" if sev in ("CRITICAL", "HIGH") else ("\033[93m" if sev == "MEDIUM" else "\033[96m")
        reset = "\033[0m"
        print(f"\n{color}[!] FIM ALERT [{sev}] {path}{reset}\n    {desc}", flush=True)
        return True

class LogFileAlertChannel:
    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        self.logger = logger_instance or logging.getLogger("fim.alerts")

    def send(self, alert_data: Dict[str, Any]) -> bool:
        sev = alert_data.get("severity", "INFO")
        msg = f"[FIM ALERT {sev}] {alert_data.get('path')}: {alert_data.get('description')}"
        if sev in ("CRITICAL", "HIGH"):
            self.logger.error(msg)
        elif sev == "MEDIUM":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)
        return True

class SlackAlertChannel:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert_data: Dict[str, Any]) -> bool:
        if not self.webhook_url:
            return False
        sev = alert_data.get("severity", "INFO")
        color = "#FF0000" if sev in ("CRITICAL", "HIGH") else ("#FFA500" if sev == "MEDIUM" else "#36A64F")
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 FIM Alert: {sev} - {alert_data.get('change_type', 'CHANGE')}",
                "fields": [
                    {"title": "File Path", "value": f"`{alert_data.get('path')}`", "short": False},
                    {"title": "Details", "value": alert_data.get("description", ""), "short": False},
                    {"title": "MITRE ATT&CK", "value": alert_data.get("attack_id", "N/A"), "short": True},
                    {"title": "New Hash", "value": f"`{alert_data.get('new_hash', 'N/A')[:16]}...`" if alert_data.get('new_hash') else "N/A", "short": True}
                ]
            }]
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(self.webhook_url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False

class TelegramAlertChannel:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send(self, alert_data: Dict[str, Any]) -> bool:
        if not self.bot_token or not self.chat_id:
            return False
        sev = alert_data.get("severity", "INFO")
        text = (
            f"🚨 *FIM Alert [{sev}]*\n"
            f"*Path:* `{alert_data.get('path')}`\n"
            f"*Change:* {alert_data.get('change_type')}\n"
            f"*Details:* {alert_data.get('description')}\n"
            f"*MITRE:* {alert_data.get('attack_id', 'None')}"
        )
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"}
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False

class WebhookAlertChannel:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, alert_data: Dict[str, Any]) -> bool:
        if not self.url:
            return False
        try:
            data = json.dumps(alert_data).encode("utf-8")
            req = urllib.request.Request(self.url, data=data, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 202, 204)
        except Exception:
            return False

class EmailAlertChannel:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config

    def send(self, alert_data: Dict[str, Any]) -> bool:
        if not self.cfg.get("sender") or not self.cfg.get("recipient"):
            return False
        try:
            msg = MIMEMultipart("alternative")
            sev = alert_data.get("severity", "INFO")
            msg["Subject"] = f"[FIM ALERT {sev}] File Integrity Change on {alert_data.get('path')}"
            msg["From"] = self.cfg.get("sender")
            msg["To"] = self.cfg.get("recipient")

            body = (
                f"Security Alert from File Integrity Monitor v2.0\n\n"
                f"Severity    : {sev}\n"
                f"Path        : {alert_data.get('path')}\n"
                f"Change Type : {alert_data.get('change_type')}\n"
                f"Description : {alert_data.get('description')}\n"
                f"MITRE ID    : {alert_data.get('attack_id')}\n"
                f"New Hash    : {alert_data.get('new_hash')}\n"
            )
            msg.attach(MIMEText(body, "plain"))

            host = self.cfg.get("smtp_host", "localhost")
            port = int(self.cfg.get("smtp_port", 587))
            with smtplib.SMTP(host, port, timeout=10) as server:
                if self.cfg.get("use_tls", True):
                    server.starttls()
                if self.cfg.get("username") and self.cfg.get("password"):
                    server.login(self.cfg["username"], self.cfg["password"])
                server.sendmail(self.cfg["sender"], [self.cfg["recipient"]], msg.as_string())
            return True
        except Exception:
            return False

class SyslogAlertChannel:
    def __init__(self, host: str = "127.0.0.1", port: int = 514, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()

    def send(self, alert_data: Dict[str, Any]) -> bool:
        try:
            msg = f"<14>1 {time_iso()} FIM - - - {json.dumps(alert_data)}"
            data = msg.encode("utf-8")
            if self.protocol == "tcp":
                with socket.create_connection((self.host, self.port), timeout=5) as s:
                    s.sendall(data)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(data, (self.host, self.port))
                s.close()
            return True
        except Exception:
            return False

def time_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
