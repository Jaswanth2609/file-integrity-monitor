# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.3.x   | :white_check_mark: |
| 2.2.x   | :white_check_mark: |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of File Integrity Monitor seriously. If you discover a security vulnerability, please follow these steps:

1. **Do not create a public GitHub issue.**
2. Send an email to Jaswanth (maintainer) via GitHub security advisories or your private contact channel.
3. Include detailed steps to reproduce the vulnerability, sample configurations, and expected vs. actual behavior.

### Security Guarantees & Scope
- **Threat Intel Privacy**: Local file contents are **NEVER** uploaded across the network. File hashes (never file contents) may be queried against VirusTotal and CIRCL's public hashlookup service for reputation checks.
- **Asymmetric Ed25519 Signatures**: Monitored endpoints only require the public key for verification, protecting against root-level baseline signature forgery.
- **HMAC Baseline Signatures**: Master secret keys must be kept secure with `0600` permissions.
- **Audit Chain & Anchoring**: The local SQLite ledger uses SHA-256 hash chaining with support for external signed chain-head anchors to detect retrospective tampering.
