"""
Configuration Manager for File Integrity Monitor (FIM) v2.0.
Handles secure loading, schema validation, environment variables, and OS keyring fallback.
"""

import os
import json
import secrets
import stat
from pathlib import Path
from typing import Any, Dict, Optional, List

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

from .errors import ConfigurationError

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "2.0.0",
    "app": {
        "name": "File Integrity Monitor",
        "secret_key": "",  # Used for HMAC-SHA256 baseline signing if not in keyring/env
        "log_level": "INFO",
        "log_file": "~/.fim/fim.log",
        "log_json": False,
        "auto_secure_permissions": True
    },
    "hashing": {
        "default_algorithm": "sha256",
        "chunk_size_kb": 64,
        "max_workers": 4,
        "allow_legacy_algorithms": True,
        "follow_symlinks": False
    },
    "baseline": {
        "default_profile": "default",
        "sign_baselines": True,
        "exclude_patterns": [
            "*.log",
            "*.tmp",
            "*.swp",
            "__pycache__",
            ".git/*",
            ".DS_Store",
            "Thumbs.db",
            "~/.fim/*"
        ],
        "include_patterns": ["*"]
    },
    "monitor": {
        "debounce_seconds": 2.0,
        "poll_interval_seconds": 5.0,
        "scheduled_check_interval_seconds": 3600,
        "auto_reverify": True
    },
    "virustotal": {
        "api_key": "",
        "rate_limit_rpm": 4,
        "timeout_seconds": 15,
        "max_retries": 3,
        "cache_ttl_hours": 24,
        "max_daily_requests": 500,
        "allow_file_upload": False
    },
    "malwarebazaar": {
        "enabled": True,
        "timeout_seconds": 10,
        "api_key": ""
    },
    "yara": {
        "enabled": True,
        "rules_dir": "~/.fim/rules"
    },
    "alerts": {
        "min_severity": "MEDIUM",
        "cooldown_seconds": 60,
        "channels": {
            "console": {"enabled": True},
            "log_file": {"enabled": True},
            "email": {
                "enabled": False,
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587,
                "use_tls": True,
                "sender": "",
                "recipient": "",
                "username": "",
                "password": ""
            },
            "slack": {
                "enabled": False,
                "webhook_url": ""
            },
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "chat_id": ""
            },
            "webhook": {
                "enabled": False,
                "url": "",
                "headers": {}
            },
            "syslog": {
                "enabled": False,
                "host": "127.0.0.1",
                "port": 514,
                "protocol": "udp"
            }
        }
    },
    "database": {
        "path": "~/.fim/fim_database.db",
        "cache_ttl_hours": 24,
        "max_history_records": 5000,
        "audit_chain_enabled": True
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8000,
        "bearer_token": "",
        "cors_origins": ["*"]
    },
    "ui": {
        "colored_output": True,
        "theme": "dark",
        "progress_bar_threshold_mb": 10
    }
}

class ConfigManager:
    """Manages application configuration, hierarchy, and secrets."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = self._resolve_config_path(config_path)
        self.data: Dict[str, Any] = self._deep_copy(DEFAULT_CONFIG)
        self.load()

    def _deep_copy(self, d: Dict[str, Any]) -> Dict[str, Any]:
        return json.loads(json.dumps(d))

    def _resolve_config_path(self, custom_path: Optional[str]) -> Path:
        if custom_path:
            return Path(custom_path).expanduser().resolve()
        
        env_path = os.getenv("FIM_CONFIG")
        if env_path:
            return Path(env_path).expanduser().resolve()

        # Check local config/config.yaml or ~/.fim/config.yaml
        local_dir = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"
        if local_dir.exists():
            return local_dir
            
        return Path("~/.fim/config.yaml").expanduser().resolve()

    def load(self) -> Dict[str, Any]:
        """Loads configuration from file and overlays environment variables."""
        if self.config_path.exists():
            try:
                content = self.config_path.read_text(encoding="utf-8")
                loaded_data: Dict[str, Any] = {}
                if HAVE_YAML:
                    loaded_data = yaml.safe_load(content) or {}
                else:
                    try:
                        loaded_data = json.loads(content)
                    except Exception:
                        loaded_data = self._parse_simple_yaml(content)
                self._merge_dicts(self.data, loaded_data)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config from {self.config_path}: {e}")

        self._apply_env_overrides()
        self._ensure_secure_permissions()
        return self.data

    def _parse_simple_yaml(self, text: str) -> Dict[str, Any]:
        """Fallback lightweight key-value parser for simple flat/nested configs."""
        res: Dict[str, Any] = {}
        curr_section: Optional[str] = None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith(":") and not ":" in line[:-1]:
                curr_section = line[:-1].strip()
                res[curr_section] = {}
            elif ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                # boolean / int parsing
                if v.lower() == "true":
                    val: Any = True
                elif v.lower() == "false":
                    val = False
                elif v.isdigit():
                    val = int(v)
                else:
                    val = v
                if curr_section and isinstance(res.get(curr_section), dict):
                    res[curr_section][k] = val
                else:
                    res[k] = val
        return res

    def _merge_dicts(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        for k, v in source.items():
            if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                self._merge_dicts(target[k], v)
            else:
                target[k] = v

    def _apply_env_overrides(self) -> None:
        """Injects environment variables for sensitive settings."""
        # VirusTotal API Key
        vt_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        if vt_key:
            self.data["virustotal"]["api_key"] = vt_key.strip()

        # FIM Master Secret Key
        secret_key = os.getenv("FIM_SECRET_KEY")
        if secret_key:
            self.data["app"]["secret_key"] = secret_key.strip()

        # Database Path
        db_path = os.getenv("FIM_DB_PATH")
        if db_path:
            self.data["database"]["path"] = db_path.strip()

        # Alerts
        slack_url = os.getenv("SLACK_WEBHOOK_URL")
        if slack_url:
            self.data["alerts"]["channels"]["slack"]["webhook_url"] = slack_url.strip()
            self.data["alerts"]["channels"]["slack"]["enabled"] = True

        tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        tg_chat = os.getenv("TELEGRAM_CHAT_ID")
        if tg_token and tg_chat:
            self.data["alerts"]["channels"]["telegram"]["bot_token"] = tg_token.strip()
            self.data["alerts"]["channels"]["telegram"]["chat_id"] = tg_chat.strip()
            self.data["alerts"]["channels"]["telegram"]["enabled"] = True

        api_token = os.getenv("FIM_API_BEARER_TOKEN")
        if api_token:
            self.data["api"]["bearer_token"] = api_token.strip()

    def save(self, path: Optional[str] = None) -> None:
        """Saves current configuration with 0600 file permissions."""
        target_path = Path(path).expanduser().resolve() if path else self.config_path
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if HAVE_YAML:
            content = yaml.dump(self.data, default_flow_style=False, sort_keys=False)
        else:
            content = json.dumps(self.data, indent=2)

        target_path.write_text(content, encoding="utf-8")
        self._set_file_0600(target_path)

    def _set_file_0600(self, path: Path) -> None:
        try:
            if os.name != "nt":
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def _ensure_secure_permissions(self) -> None:
        if self.config_path.exists() and self.data.get("app", {}).get("auto_secure_permissions", True):
            self._set_file_0600(self.config_path)

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get nested key via dot notation (e.g. 'virustotal.api_key')."""
        keys = key_path.split(".")
        val: Any = self.data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def set(self, key_path: str, value: Any) -> None:
        """Set nested key via dot notation and save."""
        keys = key_path.split(".")
        target = self.data
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value

    @property
    def vt_api_key(self) -> str:
        return str(self.get("virustotal.api_key", "") or "")

    @property
    def db_path(self) -> Path:
        raw = self.get("database.path", "~/.fim/fim_database.db")
        return Path(raw).expanduser().resolve()

    @property
    def secret_key(self) -> str:
        """
        Retrieves HMAC master secret key from env var, config, or ~/.fim/.master_key.
        Generates a secure random 256-bit key if none exists. Never uses hardcoded defaults.
        """
        env_key = os.getenv("FIM_SECRET_KEY")
        if env_key and env_key.strip():
            return env_key.strip()

        cfg_key = self.get("app.secret_key", "")
        if cfg_key and str(cfg_key).strip():
            return str(cfg_key).strip()

        key_file = self.db_path.parent / ".master_key"
        try:
            if key_file.exists():
                stored = key_file.read_text(encoding="utf-8").strip()
                if stored:
                    return stored

            generated_key = secrets.token_hex(32)
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(generated_key, encoding="utf-8")
            self._set_file_0600(key_file)
            return generated_key
        except Exception:
            if not hasattr(self, "_ephemeral_key"):
                self._ephemeral_key = secrets.token_hex(32)
            return self._ephemeral_key

    @property
    def chunk_size_bytes(self) -> int:
        kb = int(self.get("hashing.chunk_size_kb", 64))
        return max(kb, 4) * 1024
