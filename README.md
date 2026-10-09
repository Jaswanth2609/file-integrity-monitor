<<<<<<< HEAD

# File Integrity Monitor (FIM) v2.1.0
 (release: v2.1.0 - security advisories, key rotation, symlink defense, and non-blocking server)
=======
# File Integrity Monitor (FIM) v2.1.0
>>>>>>> e3b0bf9 (feat: ed25519 asymmetric signing, chain-head anchoring, YARA scanner, and hardened dashboard)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![VirusTotal API v3](https://img.shields.io/badge/VirusTotal-API%20v3-green.svg)](https://www.virustotal.com/)
[![Threat Model](https://img.shields.io/badge/Security-Threat%20Model-red.svg)](docs/THREAT_MODEL.md)

A lightweight, enterprise-grade **File Integrity Monitor (FIM)** and threat detection platform. It detects unauthorized filesystem modifications, analyzes changed files with **YARA signatures**, cross-references changes against OS package managers (`dpkg`, `rpm`, `pacman`), and supports **Asymmetric Ed25519 signing** with **external chain-head anchoring** to protect against root-level tampering.

---

## Supported Operating Systems

> [!NOTE]
> **Primary Platforms**: Linux & macOS (POSIX environments with full file permission and inode semantics).  
> **Windows**: Fully supported via **WSL2 (Windows Subsystem for Linux)**. Direct Windows native execution is experimental due to POSIX attribute differences.

---

## How Detection Works: Hash Reputation vs. YARA Content Inspection

> **Hash reputation only knows the past — YARA inspects the file itself, so it catches zero-day samples.**
>
> When a file hash has never been submitted to external threat feeds before, FIM reports `UNKNOWN` (rather than incorrectly assuming an unindexed file is safe) and routes the user to content-based detection via YARA rules.
>
> If an attacker compiles a custom payload or drops a zero-day webshell, its hash will be unindexed (`UNKNOWN`, `0/0` detections) on cloud threat feeds. FIM automatically triggers its local **YARA Inspection Engine** on added and modified files to evaluate bytecode, regex, and opcode signatures directly on disk.

---

## Key Capabilities

| Feature | Description |
|---|---|
| **Asymmetric Ed25519 Signing** | Sign baselines with private keys; monitored nodes verify using **public keys only**, preventing root-level signature forgery. |
| **External Chain-Head Anchoring** | Cryptographically anchor the append-only SHA-256 audit ledger to external WORM media, detecting local database rewrites. |
| **YARA Threat Inspection** | Automatically scans added and modified files against YARA rules (detecting webshells, reverse shells, and droppers). |
| **Package Manager Integration** | Queries `dpkg`, `rpm`, and `pacman` to eliminate false positives during routine OS updates (`apt upgrade`, `dnf update`). |
| **Symlink TOCTOU Defense** | Detects symlink replacement and redirection attacks (mapped to **MITRE ATT&CK T1036 Masquerading**). |
| **Cascade Threat Intelligence** | Multi-source hash lookup pipeline (`Local DB` → `CIRCL Hashlookup` → `VirusTotal API v3`) with rate limiting and local SQLite caching. |
| **Dashboard & Bind Security** | Multi-threaded dashboard server refuses non-loopback binds by default and enforces Bearer token authentication. |
| **User-Editable Rules** | Fully customizable detection and severity scoring defined in `config/rules.yaml`. |

---

## Quick Start Guide

### 1. (Optional) Generate Ed25519 Asymmetric Keys
Generate an Ed25519 keypair for root-tamper-resistant baseline verification:
```bash
python3 main.py keygen --out-key ~/.fim/fim_ed25519 --out-pub ~/.fim/fim_ed25519.pub
```

### 2. Create a Signed Baseline
Create a baseline snapshot of your monitored directory:
```bash
# HMAC baseline (default)
python3 main.py baseline create ./src --name src-profile

# Or Asymmetric Ed25519 baseline
python3 main.py baseline create ./src --name src-profile --sign-type ed25519 --sign-key ~/.fim/fim_ed25519
```

### 3. Verify File Integrity
Verify current filesystem state against your trusted baseline:
```bash
# Standard check
python3 main.py check --profile src-profile

# Asymmetric check using ONLY public key (tamper-proof against root on monitored host)
python3 main.py check --profile src-profile --pubkey ~/.fim/fim_ed25519.pub

# Continuous scheduled check every 5 minutes (300 seconds)
python3 main.py check --profile src-profile --interval 300
```

### 4. Export Chain-Head Anchor
Export an immutable signed anchor of the cryptographic audit ledger:
```bash
# Export signed anchor
python3 main.py audit anchor-export --output /mnt/secure_backup/chain_head.json --sign-key ~/.fim/fim_ed25519

# Verify ledger integrity against external anchor
python3 main.py audit anchor-verify --anchor /mnt/secure_backup/chain_head.json --pubkey ~/.fim/fim_ed25519.pub
```

### 5. Launch Web Dashboard & REST API
```bash
python3 main.py serve
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser for real-time monitoring and 1-click HTML/CSV/JSON report downloads.

---

## Privacy & External Queries

> [!IMPORTANT]
> **Privacy Guarantee**: File contents are **NEVER** uploaded across the network.  
> File hashes (never file contents) may be queried against VirusTotal and CIRCL's public hashlookup service for reputation analysis.

---

## Systemd & Docker Deployment

### Systemd Services
Install the provided units in `/etc/systemd/system/`:
- `systemd/fim.service`: Real-time monitoring daemon
- `systemd/fim-scan.timer`: Periodic scheduled integrity scan timer

```bash
sudo cp systemd/fim-scan.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fim-scan.timer
```

### Docker Container
```bash
docker build -t fim:v2.1 .
docker run -d -p 127.0.0.1:8000:8000 -v /etc:/monitored/etc:ro --name fim-agent fim:v2.1
```

---

## Contributing & Development

Contributions are welcome! Please follow these development steps:

1. **Clone & Virtual Environment**:
   ```bash
   git clone https://github.com/Jaswanth2609/file-integrity-monitor.git
   cd file-integrity-monitor
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run Tests**:
   ```bash
   python3 -m unittest discover -s tests -p "test_*.py"
   ```

3. **Code Quality**:
   - Maintain PEP 8 formatting via `black --line-length 100`.
   - Run security auditing via `bandit -r src/fim`.

---

## Security & Threat Model

For an in-depth breakdown of trust boundaries, attacker capabilities, and detection guarantees, refer to [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## License

Licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Jaswanth ([@Jaswanth2609](https://github.com/Jaswanth2609)).
