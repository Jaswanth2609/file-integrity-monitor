# File Integrity Monitor (FIM) v2.1 — Threat Model & Trust Assumptions

## 1. Executive Summary & Scope

File Integrity Monitor (FIM) v2.1 is designed to detect unauthorized filesystem modifications, malicious payload drops, configuration drift, and persistence mechanisms across monitored operating system directories.

This document outlines the security guarantees, attacker personas, detection boundaries, and cryptographic mitigation models implemented in FIM.

---

## 2. Attacker Personas & Threat Capabilities

```
+-----------------------------------------------------------------------------------+
| Attacker Model      | Capabilities                               | FIM Mitigation |
+---------------------+--------------------------------------------+----------------+
| Non-Root / Web App  | Can write to world-writable or app dirs    | DETECTED       |
| Attacker            | Drops webshells, modifies web scripts       | (YARA + FIM)   |
+---------------------+--------------------------------------------+----------------+
| Compromised Service | Can alter service configs, create symlinks | DETECTED       |
| Account             | TOCTOU symlink traversal attempts          | (T1036 Defense)|
+---------------------+--------------------------------------------+----------------+
| Local Root          | Can modify system files and local SQLite   | DETECTED with  |
| Attacker            | databases.                                 | Ed25519 +      |
|                     |                                            | External Anchor|
+---------------------+--------------------------------------------+----------------+
| Kernel / Ring-0     | Can subvert VFS read system calls, eBPF    | OUT OF SCOPE   |
| Rootkit             | hooks, or kernel memory directly           | (Requires WORM/|
|                     |                                            | Secure Boot)   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Cryptographic Guarantee Matrix

### 3.1 Asymmetric Ed25519 vs Symmetric HMAC

| Threat Vector | Symmetric HMAC Mode | Asymmetric Ed25519 Mode |
| :--- | :--- | :--- |
| **Non-Root Attacker Modifies Files** | **Detected** (Hash mismatch) | **Detected** (Hash mismatch) |
| **Attacker Reads Database** | No secret exposure | No secret exposure (public key only) |
| **Root Attacker Modifies Baseline DB** | Vulnerable if key is local | **Detected** (Cannot forge private key signature) |
| **Key Distribution** | Shared symmetric secret | Public key on node, Private key on admin workstation |

> [!IMPORTANT]
> **Recommended Production Deployment**: Generate Ed25519 keypairs on an isolated administrative machine (`fim keygen`). Sign baselines with the private key, and distribute **only the `.pub` public key** to monitored servers. Monitored nodes verify integrity using `fim check --pubkey /path/to/key.pub`. Even if an attacker compromises root on the target server, they lack the private key and cannot re-sign tampered baselines.

### 3.2 External Chain-Head Anchoring

To prevent a local root attacker from rewriting past entries in the SQLite audit ledger (`audit_log`) and recalculating the SHA-256 hash chain:
1. The operator exports periodic signed chain-head anchors (`fim audit anchor export --output /mnt/secure/anchor.json --sign-key admin_ed25519`).
2. The verification engine checks `fim audit anchor verify --anchor /mnt/secure/anchor.json --pubkey admin.pub`.
3. If an attacker tampers with historical records, the calculated chain-head will diverge from the immutable external anchor, flagging immediate ledger corruption.

---

## 4. What FIM Detects

- **Cryptographic File Tampering**: Bit-level modifications detected via SHA-256, SHA-512, or BLAKE2b hashing.
- **Attribute & Permission Manipulation**: File mode, permissions (`chmod 777`), ownership (`chown`), inode changes, and timestamp manipulation (timestomp).
- **Symlink Swaps & Redirection (TOCTOU Defense)**: Replacing regular files with symlinks or altering symlink targets to bypass security controls (mapped to **MITRE ATT&CK T1036**).
- **Embedded Threats & Webshells**: Automated YARA pattern scanning on added/modified files (detecting PHP/JSP webshells, reverse shells, script droppers, and crypto miners).
- **Threat Intelligence Feeds**: Real-time hash reputation lookup via VirusTotal API and MalwareBazaar malware signature database.
- **Unauthorized Package Changes vs OS Updates**: Cross-referencing file changes against system package managers (`dpkg`, `rpm`, `pacman`) to highlight unmanaged file changes while identifying official distribution updates.

---

## 5. What FIM Does NOT Detect (Limitations & Boundaries)

- **Kernel Rootkits & Direct VFS Hooks**: If an attacker installs a malicious kernel module (LKM) or eBPF program that falsifies `read()` / `stat()` system call returns before userland receives data, userland inspection tools cannot detect the deception.
- **Memory-Only (Fileless) Payloads**: Malware that executes entirely within process memory without touching the filesystem is outside the scope of file integrity monitoring.
- **Transient Ephemeral Files**: Files created and unlinked faster than the real-time debounce interval (e.g. in high-frequency scratch directories) may be missed if filesystem events are not queued by the kernel `inotify` subsystem.

---

## 6. Trust Assumptions & Hardening Recommendations

1. **Host Isolation**: Private signing keys must NEVER reside on the monitored target host.
2. **File Permissions**: Key files must have strict `0600` permissions (`owner read/write only`). FIM actively enforces this and rejects world-readable keys.
3. **API Access**: The dashboard and REST API must be bound to loopback (`127.0.0.1`) unless protected by a high-entropy Bearer token / reverse proxy with TLS.
4. **Audit Immutability**: Export chain-head anchors to write-once storage (WORM) or centralized remote logging (syslog/SIEM).
