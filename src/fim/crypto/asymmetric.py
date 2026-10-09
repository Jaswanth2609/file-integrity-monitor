"""
Asymmetric Cryptography Engine (Ed25519) for FIM v2.1.
Enables asymmetric baseline and audit-log signing, protecting against root-level tampering.
Even if an attacker gains root on a monitored host, possessing only the public key prevents
them from forging signatures or re-signing tampered baselines.
"""

import os
import stat
from pathlib import Path
from typing import Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

from .entropy import load_secure_key_file

class AsymmetricEngine:
    """Manages Ed25519 key generation, signing, and signature verification."""

    @staticmethod
    def is_available() -> bool:
        return HAVE_CRYPTOGRAPHY

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """
        Generates a new Ed25519 private/public keypair in PEM format.
        """
        if not HAVE_CRYPTOGRAPHY:
            raise RuntimeError("The 'cryptography' library is required for Ed25519 asymmetric signing.")

        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    @classmethod
    def save_keypair(
        cls,
        private_path: Union[str, Path],
        public_path: Union[str, Path]
    ) -> Tuple[Path, Path]:
        """
        Generates and saves an Ed25519 keypair with strict 0600 file permissions on the private key.
        """
        priv_pem, pub_pem = cls.generate_keypair()
        priv_p = Path(private_path).expanduser().resolve()
        pub_p = Path(public_path).expanduser().resolve()

        priv_p.parent.mkdir(parents=True, exist_ok=True)
        pub_p.parent.mkdir(parents=True, exist_ok=True)

        priv_p.write_bytes(priv_pem)
        if os.name != "nt":
            os.chmod(priv_p, stat.S_IRUSR | stat.S_IWUSR)

        pub_p.write_bytes(pub_pem)
        if os.name != "nt":
            os.chmod(pub_p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        return priv_p, pub_p

    @classmethod
    def load_private_key(cls, key_input: Union[str, Path, bytes]):
        """Loads an Ed25519 private key from PEM bytes, file path, or string."""
        if not HAVE_CRYPTOGRAPHY:
            raise RuntimeError("The 'cryptography' library is required for Ed25519 asymmetric signing.")

        if isinstance(key_input, (str, Path)) and os.path.exists(str(key_input)):
            # Enforce 0600 permissions
            p = Path(key_input).expanduser().resolve()
            if os.name != "nt":
                mode = stat.S_IMODE(p.stat().st_mode)
                if mode & 0o077 != 0:
                    raise PermissionError(
                        f"Insecure permissions on private key '{p}' ({oct(mode)}). Must be 0600."
                    )
            raw_data = p.read_bytes()
        elif isinstance(key_input, str):
            raw_data = key_input.encode("utf-8")
        else:
            raw_data = key_input

        return serialization.load_pem_private_key(raw_data, password=None)

    @classmethod
    def load_public_key(cls, key_input: Union[str, Path, bytes]):
        """Loads an Ed25519 public key from PEM bytes, file path, or string."""
        if not HAVE_CRYPTOGRAPHY:
            raise RuntimeError("The 'cryptography' library is required for Ed25519 asymmetric verification.")

        if isinstance(key_input, (str, Path)) and os.path.exists(str(key_input)):
            p = Path(key_input).expanduser().resolve()
            raw_data = p.read_bytes()
        elif isinstance(key_input, str):
            raw_data = key_input.encode("utf-8")
        else:
            raw_data = key_input

        return serialization.load_pem_public_key(raw_data)

    @classmethod
    def sign_payload(cls, payload: bytes, private_key_input: Union[str, Path, bytes]) -> str:
        """
        Signs a payload using Ed25519 private key. Returns hexadecimal signature.
        """
        priv_key = cls.load_private_key(private_key_input)
        if not isinstance(priv_key, ed25519.Ed25519PrivateKey):
            raise TypeError("Expected Ed25519PrivateKey instance.")
        sig_bytes = priv_key.sign(payload)
        return sig_bytes.hex()

    @classmethod
    def verify_payload(
        cls,
        payload: bytes,
        signature_hex: str,
        public_key_input: Union[str, Path, bytes]
    ) -> bool:
        """
        Verifies an Ed25519 signature against payload using only the public key.
        """
        try:
            pub_key = cls.load_public_key(public_key_input)
            if not isinstance(pub_key, ed25519.Ed25519PublicKey):
                raise TypeError("Expected Ed25519PublicKey instance.")
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, payload)
            return True
        except Exception:
            return False
