<<<<<<< HEAD
# File Integrity Monitor (FIM) v2.1.0
=======
# File Integrity Monitor (FIM) v2.1.0
>>>>>>> eb38af7 (release: v2.1.0 - security advisories, key rotation, symlink defense, and non-blocking server)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![VirusTotal API v3](https://img.shields.io/badge/VirusTotal-API%20v3-green.svg)](https://www.virustotal.com/)

A lightweight, enterprise-grade **File Integrity Monitor (FIM)** and threat intelligence platform in Python. It detects unauthorized file modifications, tracks added/deleted files, alerts on permission tampering, and enriches changes with **VirusTotal** and **MalwareBazaar** reputation data.

---

## Quick Start in 3 Steps

### 1. Create a Baseline
Take a cryptographically signed snapshot (HMAC-SHA256) of your target folder:
```bash
python3 main.py baseline create ./config --name config-profile
```

### 2. Verify Integrity
Compare live files against your baseline:
```bash
# Verify integrity (Exit code: 0 = Clean, 1 = Changes Found)
python3 main.py check --profile config-profile

# Export styled HTML audit report
python3 main.py check --profile config-profile --export-html reports/audit.html
```

### 3. Launch Web Dashboard & REST API
```bash
python3 main.py serve
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser for real-time monitoring and 1-click HTML/CSV/JSON report downloads.

---

## Interactive Terminal Menu

If you prefer a guided terminal UI without typing arguments, simply run:
```bash
python3 main.py
```

---

## Core Capabilities

| Feature | Description |
|---|---|
| **HMAC Baseline Signing** | Uses HMAC-SHA256 signatures to prevent tampering with baseline snapshots. |
| **Change Detection** | Detects `ADDED`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGED`, `OWNER_CHANGED`, and `RENAMED` events. |
| **MITRE ATT&CK Mapping** | Automatically scores severity (`CRITICAL` to `INFO`) and maps to MITRE techniques (`T1565`, `T1070`, `T1036`, `T1505`). |
| **Threat Intelligence** | Queries VirusTotal API v3 & MalwareBazaar (abuse.ch) with 24h caching and token-bucket rate limiting. |
| **Tamper-Evident Ledger** | Stores all scan events in an append-only, SHA-256 hash-chained SQLite audit log. |
| **Multi-Channel Alerts** | Dispatches instant alerts to Console, Log Files, Slack, Telegram, Email, and Syslog. |
| **Self-Contained** | Zero external dependencies required for core functionality; runs on standard Python 3.10+. |

---

## Configuration & Secrets

Set your optional VirusTotal API key or HMAC signing key via environment variables:
```bash
export VT_API_KEY="your_virustotal_api_key_here"
export FIM_SECRET_KEY="your_custom_signing_key"
```

---

## Running Tests

```bash
python3 -m unittest discover tests
```

---

## License
Licensed under GNU General Public License v3.0 (GPL-3.0). See [LICENSE](LICENSE) for details.

**Maintainer**: [Jaswanth (Jaswanth2609)](https://github.com/Jaswanth2609/file-integrity-monitor)
