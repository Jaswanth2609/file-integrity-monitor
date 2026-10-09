<<<<<<< HEAD

# File Integrity Monitor (FIM) v2.1.0
 (release: v2.1.0 - security advisories, key rotation, symlink defense, and non-blocking server)
=======
# File Integrity Monitor (FIM) v2.1.0
>>>>>>> e3b0bf9 (feat: ed25519 asymmetric signing, chain-head anchoring, YARA scanner, and hardened dashboard)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![VirusTotal API v3](https://img.shields.io/badge/VirusTotal-API%20v3-green.svg)](https://www.virustotal.com/)
[![Threat Model](https://img.shields.io/badge/Security-Threat%20Model-red.svg)](docs/THREAT_MODEL.md)

A lightweight, enterprise-grade **File Integrity Monitor (FIM)** and threat detection platform. It detects unauthorized filesystem modifications, analyzes changed files with **YARA signatures**, cross-references changes against OS package managers (`dpkg`, `rpm`, `pacman`), and supports **Asymmetric Ed25519 signing** with **external chain-head anchoring** to protect against root-level tampering.

---

## Supported Operating Systems

> [!NOTE]
> **Primary Platforms**: Linux & macOS (POSIX environments with full file permission and inode semantics).  
> **Windows**: Fully supported via **WSL2 (Windows Subsystem for Linux)**. Direct Windows native execution is experimental due to POSIX attribute differences.

---

## Key Capabilities

| Feature | Description |
|---|---|
| **Asymmetric Ed25519 Signing** | Sign baselines with private keys; monitored nodes verify using **public keys only**, preventing root-level signature forgery. |
| **External Chain-Head Anchoring** | Cryptographically anchor the append-only SHA-256 audit ledger to external WORM media, detecting local database rewrites. |
| **YARA Threat Inspection** | Automatically scans added and modified files against YARA rules (detecting webshells, reverse shells, and droppers). |
| **Package Manager Integration** | Queries `dpkg`, `rpm`, and `pacman` to eliminate false positives during routine OS updates (`apt upgrade`, `dnf update`). |
| **Symlink TOCTOU Defense** | Detects symlink replacement and redirection attacks (mapped to **MITRE ATT&CK T1036 Masquerading**). |
| **Threat Intelligence** | Real-time hash reputation lookups via **VirusTotal API v3** and **MalwareBazaar** with rate limiting and local SQLite caching. |
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

## Running Tests

Execute the comprehensive acceptance test suite (covering Ed25519, YARA, symlink defense, and anchoring):
```bash
python3 -m unittest discover tests
```

---

## Security & Threat Model

For an in-depth breakdown of trust boundaries, attacker capabilities, and detection guarantees, refer to [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## License
Licensed under GNU General Public License v3.0 (GPL-3.0). See [LICENSE](LICENSE) for details.

**Maintainer**: [Jaswanth (Jaswanth2609)](https://github.com/Jaswanth2609/file-integrity-monitor)
