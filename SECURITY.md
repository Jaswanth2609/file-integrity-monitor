# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of File Integrity Monitor seriously. If you discover a security vulnerability, please follow these steps:

1. **Do not create a public GitHub issue.**
2. Send an email to Jaswanth (maintainer) via GitHub security advisories or your private contact channel.
3. Include detailed steps to reproduce the vulnerability, sample configurations, and expected vs. actual behavior.

### Security Guarantees & Scope
- **Threat Intel Privacy**: Local files are never uploaded across the network. Only cryptographic hash strings (SHA-256) are transmitted for reputation checks.
- **HMAC Baseline Signatures**: Master secret keys must be kept secure. Baselines detect filesystem modifications when verified against authentic HMAC signatures.
- **Audit Chain**: The local SQLite ledger uses SHA-256 hash chaining to detect tampering or unauthorized row modifications.
