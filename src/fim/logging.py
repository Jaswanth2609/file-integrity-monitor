"""
Structured Logging Subsystem for File Integrity Monitor (FIM) v2.0.
Supports JSON format, standard text format, correlation IDs, and automated secret redaction.
"""

import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

_RUN_CORRELATION_ID: Optional[str] = None

def get_correlation_id() -> str:
    global _RUN_CORRELATION_ID
    if not _RUN_CORRELATION_ID:
        _RUN_CORRELATION_ID = str(uuid.uuid4())[:8]
    return _RUN_CORRELATION_ID

def set_correlation_id(cid: Optional[str] = None) -> str:
    global _RUN_CORRELATION_ID
    _RUN_CORRELATION_ID = cid or str(uuid.uuid4())[:8]
    return _RUN_CORRELATION_ID

def redact_secrets_text(text: str) -> str:
    """Redacts API keys, bearer tokens, and secrets from a string."""
    text = re.sub(
        r'(?i)(api[_-]?key|token|secret|password|bearer\s+)[:=\s\\"]+([a-zA-Z0-9_\-\.]{8,})',
        r'\1: [REDACTED]',
        text
    )
    return text

class SecretRedactingFormatter(logging.Formatter):
    """Redacts API keys, bearer tokens, and secrets from standard logs."""
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return redact_secrets_text(msg)

class JSONLogFormatter(logging.Formatter):
    """Formats log records as newline-delimited JSON for ELK/Splunk/Wazuh ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        msg_str = record.getMessage()
        msg_redacted = redact_secrets_text(msg_str)
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "message": msg_redacted,
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry.update(record.extra_data)
        
        serialized = json.dumps(log_entry, default=str)
        return redact_secrets_text(serialized)

def setup_logger(
    name: str = "fim",
    log_file: Optional[str] = None,
    level: str = "INFO",
    json_format: bool = False,
    console_output: bool = True
) -> logging.Logger:
    """Configures and returns a centralized FIM logger."""
    logger = logging.getLogger(name)
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    if logger.handlers:
        logger.handlers.clear()
        
    logger.propagate = False

    formatter: logging.Formatter
    if json_format:
        formatter = JSONLogFormatter()
    else:
        formatter = SecretRedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] [cid:%(correlation_id)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    old_factory = logging.getLogRecordFactory()
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id()
        return record
    logging.setLogRecordFactory(record_factory)

    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level)
        logger.addHandler(console_handler)

    if log_file:
        try:
            log_path = Path(log_file).expanduser().resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)
            try:
                os.chmod(log_path, 0o600)
            except Exception:
                pass
        except Exception as e:
            sys.stderr.write(f"Warning: Could not initialize log file handler: {e}\n")

    return logger

logger = setup_logger()
