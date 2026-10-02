"""
Error Codes and Exception Handling for File Integrity Monitor (FIM) v2.0.
"""

from typing import Optional, Dict

class FIMError(Exception):
    """Base class for all FIM exceptions."""
    def __init__(self, code: str, message: str, fix: Optional[str] = None):
        self.code = code
        self.message = message
        self.fix = fix or ERROR_REGISTRY.get(code, {}).get("fix", "Review log details.")
        super().__init__(f"[{self.code}] {self.message} (Remediation: {self.fix})")

class FileNotFoundError_(FIMError):
    def __init__(self, message: str):
        super().__init__("E001", message, "Verify file path and ensure file exists.")

class PermissionDeniedError(FIMError):
    def __init__(self, message: str):
        super().__init__("E002", message, "Run with elevated/administrative privileges or check file access rights.")

class InvalidAPIKeyError(FIMError):
    def __init__(self, message: str):
        super().__init__("E003", message, "Provide a valid API key via config or environment variable (e.g. VT_API_KEY).")

class RateLimitExceededError(FIMError):
    def __init__(self, message: str):
        super().__init__("E004", message, "Wait for the rate-limit window or reduce scan request frequency.")

class NetworkError(FIMError):
    def __init__(self, message: str):
        super().__init__("E005", message, "Verify internet connectivity and DNS resolution.")

class InvalidHashFormatError(FIMError):
    def __init__(self, message: str):
        super().__init__("E006", message, "Provide a valid hex hash string (MD5, SHA-1, SHA-256, or SHA-512).")

class DatabaseError(FIMError):
    def __init__(self, message: str):
        super().__init__("E007", message, "Check database permissions, lock status, or disk space.")

class ConfigurationError(FIMError):
    def __init__(self, message: str):
        super().__init__("E008", message, "Check YAML/JSON syntax and required fields in configuration.")

class BaselineTamperedError(FIMError):
    def __init__(self, message: str):
        super().__init__("E009", message, "Baseline HMAC signature verification failed. Possible unauthorized tampering detected!")

class AuditChainBrokenError(FIMError):
    def __init__(self, message: str):
        super().__init__("E010", message, "Audit log hash chain is broken or records have been modified/deleted.")

class AlertDeliveryError(FIMError):
    def __init__(self, message: str):
        super().__init__("E011", message, "Check alert webhook URL, SMTP credentials, or network route.")

class MonitorServiceError(FIMError):
    def __init__(self, message: str):
        super().__init__("E012", message, "Verify filesystem watcher permissions and service configuration.")


ERROR_REGISTRY: Dict[str, Dict[str, str]] = {
    "E001": {
        "title": "File Not Found",
        "description": "The specified file or directory could not be located on the filesystem.",
        "fix": "Verify that the path is correct and accessible."
    },
    "E002": {
        "title": "Permission Denied",
        "description": "Operating system denied read or write access to the file or directory.",
        "fix": "Run the command with sufficient privileges or adjust file ownership/permissions."
    },
    "E003": {
        "title": "Invalid VirusTotal API Key",
        "description": "The provided VirusTotal API key is missing, malformed, or rejected by the API.",
        "fix": "Set a valid 64-character API key in config or via VT_API_KEY environment variable."
    },
    "E004": {
        "title": "Rate Limit Exceeded",
        "description": "Threat intelligence request rate exceeds allowed limits (e.g. 4 req/min on VT free tier).",
        "fix": "Rely on local cache or lower query concurrency."
    },
    "E005": {
        "title": "Network Error",
        "description": "Failed to communicate with external threat intelligence or webhook services.",
        "fix": "Verify internet connectivity, firewall rules, and proxy settings."
    },
    "E006": {
        "title": "Invalid Hash Format",
        "description": "Input string does not match any standard hexadecimal hash length.",
        "fix": "Ensure hash is 32 (MD5), 40 (SHA-1), 64 (SHA-256), or 128 (SHA-512) hex digits."
    },
    "E007": {
        "title": "Database Error",
        "description": "An SQLite database operation failed.",
        "fix": "Check database file permissions, storage availability, and verify file is not locked."
    },
    "E008": {
        "title": "Configuration Error",
        "description": "Failed to parse or validate application configuration file.",
        "fix": "Check YAML syntax and verify parameter values against schema."
    },
    "E009": {
        "title": "Baseline Tampering Detected",
        "description": "Cryptographic signature (HMAC-SHA256) of baseline does not match recorded state.",
        "fix": "Investigate system for unauthorized baseline alterations or re-sign using authentic master key."
    },
    "E010": {
        "title": "Audit Log Chain Integrity Failure",
        "description": "Audit log hash chain validation failed. Records may have been deleted or modified.",
        "fix": "Review audit database immediately for tampering; restore from secure remote replica."
    },
    "E011": {
        "title": "Alert Delivery Failure",
        "description": "Failed to dispatch notification to configured alert channels.",
        "fix": "Verify SMTP credentials, webhook endpoints, bot tokens, or syslog daemon connectivity."
    },
    "E012": {
        "title": "Monitor Service Failure",
        "description": "Filesystem watcher event pipeline encountered an unrecoverable failure.",
        "fix": "Check OS inotify/file watch limits and ensure watched paths exist."
    },
}

def format_error(code: str, custom_message: Optional[str] = None) -> str:
    info = ERROR_REGISTRY.get(code, {"title": "Unknown Error", "description": "An error occurred.", "fix": "Check logs."})
    msg = custom_message or info["description"]
    return f"[{code}] {info['title']}: {msg}\nTroubleshooting: {info['fix']}"
