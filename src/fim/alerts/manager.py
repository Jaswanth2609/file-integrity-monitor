"""
Alert Manager for FIM v2.0.
Handles minimum severity thresholds, cooldown de-duplication, and channel dispatching.
"""

import time
from typing import Any, Dict, List, Optional

from .channels import (
    ConsoleAlertChannel,
    EmailAlertChannel,
    LogFileAlertChannel,
    SlackAlertChannel,
    SyslogAlertChannel,
    TelegramAlertChannel,
    WebhookAlertChannel
)
from ..config import ConfigManager
from ..core.rules import Severity
from ..storage.db import DatabaseManager

class AlertManager:
    """Manages alert routing, filtering, and throttling."""

    def __init__(self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.min_sev = self.config.get("alerts.min_severity", "MEDIUM")
        self.cooldown_seconds = float(self.config.get("alerts.cooldown_seconds", 60.0))
        self.last_sent: Dict[str, float] = {}
        self._init_channels()

    def _init_channels(self) -> None:
        self.channels: Dict[str, Any] = {}
        ch_cfg = self.config.get("alerts.channels", {})

        if ch_cfg.get("console", {}).get("enabled", True):
            self.channels["console"] = ConsoleAlertChannel()

        if ch_cfg.get("log_file", {}).get("enabled", True):
            self.channels["log_file"] = LogFileAlertChannel()

        slack_cfg = ch_cfg.get("slack", {})
        if slack_cfg.get("enabled") and slack_cfg.get("webhook_url"):
            self.channels["slack"] = SlackAlertChannel(slack_cfg["webhook_url"])

        tg_cfg = ch_cfg.get("telegram", {})
        if tg_cfg.get("enabled") and tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
            self.channels["telegram"] = TelegramAlertChannel(tg_cfg["bot_token"], tg_cfg["chat_id"])

        email_cfg = ch_cfg.get("email", {})
        if email_cfg.get("enabled"):
            self.channels["email"] = EmailAlertChannel(email_cfg)

        hook_cfg = ch_cfg.get("webhook", {})
        if hook_cfg.get("enabled") and hook_cfg.get("url"):
            self.channels["webhook"] = WebhookAlertChannel(hook_cfg["url"], hook_cfg.get("headers"))

        syslog_cfg = ch_cfg.get("syslog", {})
        if syslog_cfg.get("enabled"):
            self.channels["syslog"] = SyslogAlertChannel(
                syslog_cfg.get("host", "127.0.0.1"),
                int(syslog_cfg.get("port", 514)),
                syslog_cfg.get("protocol", "udp")
            )

    def dispatch(self, finding_data: Dict[str, Any], finding_id: Optional[int] = None) -> Dict[str, bool]:
        """Dispatches finding alert to all active channels respecting severity and cooldown."""
        sev_str = finding_data.get("severity", "INFO")
        if Severity.rank(sev_str) < Severity.rank(self.min_sev):
            return {}

        path = finding_data.get("path", "")
        now = time.time()
        cooldown_key = f"{path}:{finding_data.get('change_type')}"

        if cooldown_key in self.last_sent:
            if now - self.last_sent[cooldown_key] < self.cooldown_seconds:
                # Suppressed due to cooldown
                return {}

        self.last_sent[cooldown_key] = now
        results: Dict[str, bool] = {}

        for ch_name, channel in self.channels.items():
            try:
                ok = channel.send(finding_data)
                results[ch_name] = ok
            except Exception:
                results[ch_name] = False

        return results
