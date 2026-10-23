# File Integrity Monitor (FIM)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Threat Model](https://img.shields.io/badge/Security-Threat%20Model-red.svg)](docs/THREAT_MODEL.md)

A lightweight filesystem integrity monitoring and threat detection utility for Linux and macOS. It computes cryptographic baselines of target directories, detects unauthorized changes to file contents and metadata, verifies baselines using HMAC or asymmetric Ed25519 signatures, and logs events to an append-only cryptographic audit ledger.

---

## Supported Operating Systems

- **Linux & macOS**: Primary supported platforms. Requires POSIX filesystem semantics (standard file permissions, ownership, and inode behavior).
- **Windows**: Supported via **WSL2 (Windows Subsystem for Linux)**. Direct Windows native execution is unsupported due to differences in file metadata and POSIX permission models.

---

## How Detection Works

### Content Inspection vs. Hash Reputation

Hash reputation services (VirusTotal, CIRCL Hashlookup) only contain records for files that have been analyzed previously. When a file hash is not present in external threat databases:

1. FIM marks the result as `UNKNOWN` (`0/0` detections) rather than assuming an unindexed file is benign.
2. FIM runs its local **YARA Inspection Engine** on added and modified files to evaluate bytecode, regex, and opcode signatures directly on disk.

This catches custom payloads, modified scripts, and webshells whose hashes have never been submitted to public repositories.

### Package Manager Verification

To distinguish legitimate administrative updates from unauthorized file modifications, FIM cross-references modified system files against local package managers (`dpkg`, `rpm`, `pacman`). Changes matching package manager checksums can be filtered or downgraded in severity.

### Symlink Resolution & TOCTOU Defense

FIM tracks canonical paths and file descriptors to mitigate time-of-check to time-of-use (TOCTOU) symlink substitution attacks (MITRE ATT&CK T1036 Masquerading).

---

## Security Model & Cryptographic Guarantees

For full details on threat actors, trust assumptions, and boundaries, consult [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

### Baseline Verification (HMAC vs. Ed25519)

| Feature | Symmetric HMAC Mode | Asymmetric Ed25519 Mode |
|---|---|---|
| **Key Type** | Single secret key | Public / Private keypair |
| **Monitored Node Key** | Requires shared secret key | Requires **public key only** |
| **Protection Against Local Root** | Vulnerable if key is stored locally | **Protected**: Local root cannot forge private key signatures |
| **Typical Use Case** | Single-host deployments | Centralized admin workstation signing; edge node verification |

**Recommended Production Workflow**: Generate the Ed25519 keypair on a secure administration workstation (`fim keygen`). Sign baselines with the private key. Distribute only the public key (`.pub`) to monitored servers. Monitored servers verify integrity using `fim check --pubkey <path>`. Even if an attacker gains root access on the monitored node, they cannot forge a valid signature for a modified baseline.

### Audit Ledger & External Anchoring

- Every verification run, baseline modification, and alert is recorded in an SQLite database using an append-only SHA-256 hash chain (`audit_log`).
- Operators can export the chain-head hash signed with Ed25519 (`fim audit anchor-export`) to external storage (such as a remote syslog host or WORM media).
- Running `fim audit anchor-verify` validates the local ledger against the external anchor, detecting any retroactive modifications or row deletions.

### Scope Limitations

- **Kernel Rootkits & VFS Hooks**: Attackers with kernel-level access (LKM or eBPF) that intercept `read()` or `stat()` system call returns can spoof file content before it reaches userland processes.
- **Fileless Malware**: In-memory payloads that never write to the filesystem are out of scope.

---

## Installation

### Requirements

- Python >= 3.10
- Linux or macOS (or WSL2 on Windows)

### Setup

```bash
git clone https://github.com/Jaswanth2609/file-integrity-monitor.git
cd file-integrity-monitor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Install CLI globally in editable mode
pip install -e .
```

Core runtime dependencies: `cryptography`, `pyyaml`, `requests`, `watchdog`.

---

## Command Reference

> [!TIP]
> Commands can be run using either the installed entry point (`fim <command>`) or directly via Python (`python3 main.py <command>`). Running `python3 main.py` without arguments launches the interactive terminal menu.

### Quick Start: Interactive Menu

Launch the interactive terminal interface:
```bash
python3 main.py
# or
fim menu
```

### 1. Key Generation (Ed25519)

Generate an asymmetric keypair for baseline and anchor signing:
```bash
python3 main.py keygen --out-key ~/.fim/fim_ed25519 --out-pub ~/.fim/fim_ed25519.pub
# or: fim keygen --out-key ~/.fim/fim_ed25519 --out-pub ~/.fim/fim_ed25519.pub
```

### 2. Baseline Management

Create a signed baseline profile for one or more directories:
```bash
# Symmetric HMAC baseline (default)
fim baseline create /etc /usr/local/bin --name sys-profile --algo sha256

# Asymmetric Ed25519 baseline (signed with private key)
fim baseline create /etc /usr/local/bin --name sys-profile --sign-type ed25519 --sign-key ~/.fim/fim_ed25519

# List existing profiles
fim baseline list

# Compare two baselines
fim baseline diff profile-v1 profile-v2
```

### 3. Integrity Verification

Check current filesystem state against a stored baseline:
```bash
# Standard HMAC verification
fim check --profile sys-profile

# Asymmetric verification using ONLY the public key
fim check --profile sys-profile --pubkey ~/.fim/fim_ed25519.pub

# Scheduled recurring check (e.g. every 5 minutes / 300 seconds)
fim check --profile sys-profile --pubkey ~/.fim/fim_ed25519.pub --interval 300

# Export results to HTML, JSON, or CSV
fim check --profile sys-profile --export-html report.html --export-json report.json
```

### 4. Real-Time Monitoring Daemon

Monitor filesystem events continuously using filesystem notifications:
```bash
fim watch --profile sys-profile --public-key ~/.fim/fim_ed25519.pub
```

### 5. Audit Ledger & Chain Anchoring

Inspect and verify the cryptographic audit trail:
```bash
# Verify internal hash chain consistency
fim audit verify

# Export and sign current chain-head anchor
fim audit anchor-export --output /mnt/backup/chain_head.json --sign-key ~/.fim/fim_ed25519

# Verify ledger integrity against an external anchor
fim audit anchor-verify --anchor /mnt/backup/chain_head.json --pubkey ~/.fim/fim_ed25519.pub
```

### 6. File & Hash Utilities

```bash
# Scan a single file or directory for threats (reputation + local YARA)
fim scan /path/to/suspect_file

# Compute cryptographic hashes for a file
fim hash /path/to/file --algo sha256

# Verify SQLite database consistency
fim db verify
```

### 7. HTTP API & Web Dashboard

Launch the embedded HTTP server:
```bash
fim serve --host 127.0.0.1 --port 8000
```

- **Loopback Enforcement**: The server refuses to bind to non-loopback addresses (`0.0.0.0`) unless `--allow-remote` is explicitly passed.
- **Authentication**: On startup, a cryptographically secure 256-bit token is saved to `.api_token` with `0600` file permissions. All requests must provide this token via the `Authorization: Bearer <token>` or `X-API-Key: <token>` header.
- **Endpoints**:
  - `GET /health` — Service status
  - `GET /api/status` — System summary and metrics
  - `GET /api/baselines` — List registered baselines
  - `GET /api/findings` — Query detected integrity anomalies
  - `GET /api/reports/download?format=html|json|csv` — Export reports
  - `GET /metrics` — Prometheus metrics format

### 8. Interactive Menu

For guided interactive configuration:
```bash
fim menu
```

---

## Configuration

Configuration files are located in `config/`:
- `config/config.yaml`: Core settings (database path, hashing algorithm, chunk size, alert channels, API settings).
- `config/rules.yaml`: Rule definitions, path exclusion patterns, and severity weights.

Example `config/config.yaml` excerpt:
```yaml
core:
  hash_algorithm: "sha256"
  chunk_size_bytes: 65536
  database_path: "~/.fim/fim.db"

alerts:
  console:
    enabled: true
  file:
    enabled: true
    path: "~/.fim/fim_alerts.log"
  syslog:
    enabled: false
```

---

## Deployment

### Systemd Units

Systemd service and timer definitions are provided in `systemd/`:
- `fim.service`: Continuous watcher daemon.
- `fim-scan.service` & `fim-scan.timer`: Periodic scheduled integrity scan.

Installation:
```bash
sudo cp systemd/fim-scan.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fim-scan.timer
```

### Docker

Build and run in a minimal container running as a non-privileged user:
```bash
docker build -t fim:v2.3.0 .
docker run -d \
  -p 127.0.0.1:8000:8000 \
  -v /etc:/monitored/etc:ro \
  --name fim-agent fim:v2.3.0
```

---

## Privacy Statement

- **File contents are never transmitted across the network.**
- When external threat intelligence lookups are enabled, only cryptographic file hashes (never filenames or contents) are queried against VirusTotal (API v3) and CIRCL Hashlookup.

---

## Testing & Code Quality

Run the test suite:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Run code formatting, linting, and security audits:
```bash
# Format check
black --check .

# Lint check
ruff check .

# Static application security testing (SAST)
bandit -r src/ -ll
```

---

## Contributing

1. Fork the repository and create a feature branch (`git checkout -b feature/name`).
2. Verify all 40 unit tests pass (`python3 -m unittest discover -s tests -p "test_*.py"`).
3. Ensure formatting conforms to `black` (line length 100) and `ruff`.
4. Open a pull request describing the changes and testing performed.

---

## License

This project is licensed under the [MIT License](LICENSE).
