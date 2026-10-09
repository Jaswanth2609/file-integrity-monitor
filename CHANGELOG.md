# File Integrity Monitor (FIM) — Project Notice, Contributing & Changelog

---

## 1. Project Notice & Legal Attribution

```text
File Integrity Monitor (FIM) v2.1.0
Copyright (C) 2026 Jaswanth (Jaswanth2609)
Repository: https://github.com/Jaswanth2609/file-integrity-monitor

Author & Maintainer : Jaswanth (Jaswanth2609)
License             : GNU General Public License v3.0 (GPL-3.0)
```

This software is provided under the terms of the GNU General Public License v3.0. You may redistribute it and/or modify it under the terms of the GNU GPL as published by the Free Software Foundation. See the [LICENSE](LICENSE) file for the full text.

---

## 2. Contributing Guidelines & Development Workflow

Thank you for your interest in contributing to File Integrity Monitor! Please follow these standards when developing features, fixing issues, or submitting pull requests.

### Development Environment Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Jaswanth2609/file-integrity-monitor.git
   cd file-integrity-monitor
   ```

2. **Set Up Python Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Run the Test Suite**:
   Always ensure that all acceptance tests pass before submitting changes:
   ```bash
   python3 -m unittest discover -s tests -p "test_*.py"
   ```

4. **Code Style & Security Guidelines**:
   - **Formatting**: Maintain clean PEP 8 standards with `black --line-length 100`.
   - **Linting**: Check code quality with `ruff check .`.
   - **Security Audit**: Run static security analysis with `bandit -r src/fim`.
   - **Permissions**: Ensure key files and databases maintain strict `0600` permissions.

---

## 3. Comprehensive Changelog

All notable changes across versions of File Integrity Monitor are documented below following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standards and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

### [2.1.0] - 2026-10-09

#### Cryptographic Hardening & Asymmetric Security
- **Asymmetric Ed25519 Baseline Signing**: Implemented `AsymmetricEngine` (`fim keygen`, `fim baseline create --sign-type ed25519`). Monitored endpoints only require the public key for verification, preventing root attackers on target hosts from forging or re-signing tampered baselines.
- **External Chain-Head Anchoring**: Implemented `ChainAnchorManager` (`fim audit anchor-export` / `fim audit anchor-verify`) to sign and anchor the immutable SHA-256 audit ledger head to external WORM media, detecting retrospective database rewrites.
- **Dynamic HMAC Key Generation & Entropy Checks**: Replaced hardcoded fallback keys with dynamic 256-bit keys persisted with strict `0600` permissions. Implemented Shannon entropy validation (`validate_secret_entropy`) to reject weak secrets.
- **Explicit Key Migration Protocol**: Added `fim baseline migrate` and `--accept-migration` flags ensuring key migrations require explicit operator consent.

#### Threat Intelligence & Detection
- **Cascade Threat Intelligence Pipeline**: Multi-source pipeline querying `Local DB` → `CIRCL Hashlookup (NSRL)` → `VirusTotal API v3` without burning API quotas.
- **YARA Threat Inspection Engine**: Added `YaraEngine` supporting both native `yara-python` and an automatic pure-Python fallback to detect webshells, reverse shells, script droppers, and crypto miners on added/modified files.
- **Clear `UNKNOWN` vs `Safe` Framing**: Hash reputation only tracks past submissions; when unindexed (`0/0` detections), FIM explicitly labels files as `UNKNOWN` and routes analysis to local YARA content inspection.
- **Package Manager Verification (`dpkg`, `rpm`, `pacman`)**: Automatically queries Linux package managers to cross-reference system changes and eliminate false positives during routine OS updates (`apt upgrade`).
- **Symlink TOCTOU Defense**: Full symlink resolution and swap detection mapped to **MITRE ATT&CK T1036 Masquerading**.

#### Operations & Deployment
- **User-Editable Rules**: Published detection rules and severity mappings to `config/rules.yaml`.
- **Hardened Dashboard Server**: Refuses non-loopback network binds by default (`--allow-remote` required) and enforces Bearer token authentication on all API routes.
- **Systemd & Docker Integration**: Added `systemd/fim.service`, `systemd/fim-scan.service`, `systemd/fim-scan.timer`, and a hardened multi-stage `Dockerfile`.
- **Scheduled Scan Mode**: Added `fim check --interval <seconds>` for continuous autonomous scanning.
- **Threat Model**: Published comprehensive threat model documentation in `docs/THREAT_MODEL.md`.

---

### [2.0.0] - 2026-10-02

#### Added
- **Cryptographic Baseline Management**: HMAC-SHA256 signed snapshots per directory tree with versioning, diffing, and change acceptance.
- **Advanced Change Detection**: Detects `ADDED`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGED`, `OWNER_CHANGED`, and `RENAMED` events.
- **MITRE ATT&CK Mapping**: Automatic severity scoring (`CRITICAL` to `INFO`) and tactic correlation (`T1565`, `T1070`, `T1036`, `T1505`, `T1059`).
- **Real-Time Monitoring**: Live filesystem event watcher with event debouncing and scheduled verification.
- **Threat Intelligence**: VirusTotal API v3 hash reputation client with token-bucket rate limiting and 24h SQLite caching.
- **Multi-Channel Alerting**: Dispatches instant alerts to Console, Log File, Email, Slack, Telegram, Webhooks, and Syslog.
- **Append-Only Audit Chain**: Tamper-evident SHA-256 hash-chained ledger storing all system events.
- **REST API & Web Dashboard**: Multi-threaded FastAPI/HTTP server with Prometheus metrics and dark-mode web dashboard.
- **Multi-Format Reporting**: Export audit findings to interactive HTML, schema-compliant JSON, CSV, and TXT.

#### Changed
- Default hashing algorithm upgraded to SHA-256 (with SHA-512 and BLAKE2b options).
- Enforced restrictive `0600` file permissions on databases, configs, and reports.

---

### [1.0.0] - 2026-09-01
- Initial release with basic CLI hash checking, dual MD5/SHA-256 calculation, and VirusTotal lookup.
