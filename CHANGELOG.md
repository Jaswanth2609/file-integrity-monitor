# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-02

### Added
- **True Baseline Management**: Cryptographically signed snapshots (HMAC-SHA256) per directory tree with versioning, diffing, and change acceptance.
- **Advanced Change Detection**: Detects `ADDED`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGED`, `OWNER_CHANGED`, and `RENAMED` events.
- **Rule Engine & MITRE ATT&CK Mapping**: Automatic severity scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and MITRE technique correlation (e.g. `T1565`, `T1070`, `T1036`, `T1505`, `T1059`).
- **Real-Time Monitoring**: Live filesystem event watcher with event debouncing (default 2s) and scheduled re-verification.
- **Threat Intelligence Enrichment**:
  - VirusTotal API v3 hash reputation client with token-bucket rate limiting and daily quota tracking.
  - MalwareBazaar (abuse.ch) free secondary feed integration.
  - Local heuristic signature rule scanner for webshells and reverse shells.
  - Persistent SQLite cache (24h default TTL) ensuring zero redundant queries.
- **Multi-Channel Alerting**: Real-time dispatching to Console, Log File, SMTP Email, Slack Webhook, Telegram Bot, Custom Webhooks, and Syslog daemon.
- **Tamper-Evident Audit Chain**: Append-only hash-chained ledger storing all system and scan events with cryptographic verification.
- **REST API & Web Dashboard**:
  - Standalone FastAPI/HTTP service exposing `/baselines`, `/checks`, `/findings`, `/alerts`, `/health`, and Prometheus `/metrics`.
  - Modern dark-mode glassmorphic single-page dashboard with real-time updates and interactive action controls.
- **Multi-Format Reporting**: Export audit findings to interactive HTML with summary charts, schema-compliant JSON, CSV, and formatted TXT.
- **Robust CLI**: Unified CLI subcommands (`fim baseline`, `fim check`, `fim watch`, `fim scan`, `fim hash`, `fim report`, `fim config`, `fim serve`, `fim menu`).
- **DevOps & Testing**:
  - Comprehensive pytest test suite (TC-001 through TC-022).
  - GitHub Actions CI/CD workflows for multi-OS/matrix testing and releases.

### Changed
- Default hashing algorithm upgraded to SHA-256 (with SHA-512 and BLAKE2b options; MD5/SHA-1 relegated to legacy warnings).
- Secrets and API keys now strictly loaded from environment variables or OS keyring; automatic redaction in logs.
- Enforced restrictive 0600 file permissions on databases, configs, and reports.

---

## [1.0.0] - 2026-09-01
- Initial release with basic CLI hash checking, dual MD5/SHA-256 calculation, and VirusTotal lookup.
