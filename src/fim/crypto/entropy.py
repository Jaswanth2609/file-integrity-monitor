"""
Cryptographic Entropy and Key Safety Validator for FIM v2.1.
Calculates Shannon entropy, enforces file-based 0600 key storage, and prevents low-entropy secrets.
"""

import math
import os
import secrets
import stat
from pathlib import Path
from typing import Tuple, Union


def calculate_shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calculates the Shannon entropy (in bits per symbol) for a string or byte sequence.
    Maximum entropy for bytes (256 distinct values) is 8.0 bits/byte.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        byte_seq = data.encode("utf-8")
    else:
        byte_seq = data

    length = len(byte_seq)
    if length == 0:
        return 0.0

    frequencies = {}
    for b in byte_seq:
        frequencies[b] = frequencies.get(b, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def validate_secret_entropy(
    secret: str, min_length: int = 16, min_entropy: float = 3.5
) -> Tuple[bool, str]:
    """
    Validates that a master key or passphrase meets minimum length and entropy thresholds.
    """
    if not secret:
        return False, "Secret key cannot be empty."

    s_clean = secret.strip()
    if len(s_clean) < min_length:
        return (
            False,
            f"Secret key length ({len(s_clean)}) is less than minimum required length ({min_length} chars).",
        )

    ent = calculate_shannon_entropy(s_clean)
    if ent < min_entropy:
        return (
            False,
            f"Secret key entropy ({ent:.2f} bits/symbol) is below minimum threshold ({min_entropy:.2f}). Use a high-entropy random key.",
        )

    return True, f"Entropy validation passed ({ent:.2f} bits/symbol)."


def load_secure_key_file(
    key_path: Union[str, Path], enforce_permissions: bool = True, auto_generate: bool = False
) -> str:
    """
    Loads a key from a file, enforcing strict POSIX file permissions (0600) and entropy check.
    If auto_generate is True, generates a high-entropy 256-bit key if the file does not exist.
    """
    p = Path(key_path).expanduser().resolve()
    if not p.exists():
        if auto_generate:
            p.parent.mkdir(parents=True, exist_ok=True)
            generated = secrets.token_hex(32)
            p.write_text(generated, encoding="utf-8")
            if os.name != "nt":
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
            return generated
        raise FileNotFoundError(f"Key file '{p}' does not exist.")

    if enforce_permissions and os.name != "nt":
        file_stat = p.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        # Check if group or others have read/write/execute permissions (mask 0077)
        if mode & 0o077 != 0:
            raise PermissionError(
                f"Insecure file permissions on key file '{p}' (mode: {oct(mode)}). "
                f"Key files must have permissions 0600 (owner read/write only). Run: chmod 600 '{p}'"
            )

    content = p.read_text(encoding="utf-8").strip()
    valid, msg = validate_secret_entropy(content, min_length=16, min_entropy=3.5)
    if not valid:
        raise ValueError(f"Key file '{p}' failed security check: {msg}")

    return content
