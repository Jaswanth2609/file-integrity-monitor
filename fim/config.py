"""
Configuration Manager for File Integrity Monitor.
Handles loading, saving, and overriding configuration settings.
"""

import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "virustotal": {
        "api_key": "",
        "rate_limit_rpm": 4,
        "timeout_seconds": 15,
        "max_retries": 3,
    },
    "database": {
        "path": "~/.fim/fim_database.db",
        "cache_ttl_hours": 24,
        "max_history_records": 1000,
    },
    "ui": {
        "colored_output": True,
        "progress_bar_threshold_mb": 10,
    },
    "scanner": {
        "chunk_size_kb": 64,
        "memory_threshold_mb": 300,
    },
}

class ConfigManager:
    """Manages application configuration with YAML/JSON fallback and environment variable support."""

    def __init__(self, config_path: str = None):
        if config_path:
            self.config_path = Path(config_path).expanduser().resolve()
        else:
            # Look in local project config/config.yaml first, then ~/.fim/config.yaml
            local_config = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
            if local_config.exists():
                self.config_path = local_config
            else:
                user_fim_dir = Path("~/.fim").expanduser()
                user_fim_dir.mkdir(parents=True, exist_ok=True)
                self.config_path = user_fim_dir / "config.yaml"

        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Loads configuration from file and applies defaults & environment overrides."""
        cfg = {}
        for section, values in DEFAULT_CONFIG.items():
            cfg[section] = values.copy()

        if self.config_path.exists():
            try:
                import yaml
                with open(self.config_path, "r", encoding="utf-8") as f:
                    file_cfg = yaml.safe_load(f)
                    if isinstance(file_cfg, dict):
                        for sec, val in file_cfg.items():
                            if isinstance(val, dict) and sec in cfg:
                                cfg[sec].update(val)
                            else:
                                cfg[sec] = val
            except Exception as e:
                # If error parsing, keep defaults
                pass

        # Environment variable overrides
        env_vt_key = os.getenv("VT_API_KEY")
        if env_vt_key:
            cfg["virustotal"]["api_key"] = env_vt_key.strip()

        return cfg

    def save(self) -> bool:
        """Saves current configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            import yaml
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            return True
        except Exception:
            return False

    def get(self, key_path: str, default: Any = None) -> Any:
        """Access config via dot-notation like 'virustotal.api_key'."""
        parts = key_path.split(".")
        val = self.config
        for part in parts:
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                return default
        return val

    def set(self, key_path: str, value: Any) -> None:
        """Set config via dot-notation."""
        parts = key_path.split(".")
        val = self.config
        for part in parts[:-1]:
            if part not in val or not isinstance(val[part], dict):
                val[part] = {}
            val = val[part]
        val[parts[-1]] = value

    @property
    def vt_api_key(self) -> str:
        return self.get("virustotal.api_key", "").strip()

    @vt_api_key.setter
    def vt_api_key(self, key: str) -> None:
        self.set("virustotal.api_key", key.strip())

    @property
    def database_path(self) -> str:
        raw = self.get("database.path", "~/.fim/fim_database.db")
        return str(Path(raw).expanduser().resolve())

    @property
    def cache_ttl_hours(self) -> int:
        return int(self.get("database.cache_ttl_hours", 24))

    @property
    def rate_limit_rpm(self) -> int:
        return int(self.get("virustotal.rate_limit_rpm", 4))

    @property
    def chunk_size(self) -> int:
        return int(self.get("scanner.chunk_size_kb", 64)) * 1024

    @property
    def colored_output(self) -> bool:
        return bool(self.get("ui.colored_output", True))
