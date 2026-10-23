"""
External Chain-Head Anchoring Engine for FIM v2.3.
Enables cryptographic anchoring of the append-only audit chain head to external media, WORM storage,
or remote audit endpoints.
Protects against root attackers attempting to rewrite local SQLite audit records and recompute hashes.
"""

import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from .asymmetric import AsymmetricEngine


class ChainAnchorManager:
    """Manages creation, signing, exporting, and verification of audit chain-head anchors."""

    @classmethod
    def create_anchor(
        cls,
        sequence_id: int,
        chain_head_hash: str,
        total_events: int,
        private_key_path: Optional[Union[str, Path]] = None,
        secret_hmac_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a signed anchor document for the current audit chain head.
        """
        ts = time.time()
        anchor_data: Dict[str, Any] = {
            "version": "1.0",
            "sequence_id": sequence_id,
            "chain_head_hash": chain_head_hash,
            "total_events": total_events,
            "anchored_at": ts,
            "metadata": metadata or {},
            "signing_type": "none",
            "signature": "",
        }

        canonical_payload = cls._canonicalize_anchor_payload(anchor_data)

        if private_key_path and AsymmetricEngine.is_available():
            sig = AsymmetricEngine.sign_payload(canonical_payload, private_key_path)
            anchor_data["signing_type"] = "ed25519"
            anchor_data["signature"] = sig
        elif secret_hmac_key:
            sig = hmac.new(
                secret_hmac_key.encode("utf-8"), canonical_payload, hashlib.sha256
            ).hexdigest()
            anchor_data["signing_type"] = "hmac_sha256"
            anchor_data["signature"] = sig

        return anchor_data

    @classmethod
    def _canonicalize_anchor_payload(cls, anchor_data: Dict[str, Any]) -> bytes:
        payload_dict = {
            "version": anchor_data.get("version", "1.0"),
            "sequence_id": anchor_data.get("sequence_id", 0),
            "chain_head_hash": anchor_data.get("chain_head_hash", ""),
            "total_events": anchor_data.get("total_events", 0),
            "anchored_at": f"{anchor_data.get('anchored_at', 0.0):.6f}",
        }
        return json.dumps(payload_dict, sort_keys=True).encode("utf-8")

    @classmethod
    def export_anchor_file(cls, anchor_data: Dict[str, Any], output_path: Union[str, Path]) -> Path:
        """Exports anchor data to JSON file."""
        p = Path(output_path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(anchor_data, indent=2), encoding="utf-8")
        return p

    @classmethod
    def load_anchor_file(cls, input_path: Union[str, Path]) -> Dict[str, Any]:
        """Loads anchor data from JSON file."""
        p = Path(input_path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Anchor file '{p}' does not exist.")
        return json.loads(p.read_text(encoding="utf-8"))

    @classmethod
    def verify_anchor(
        cls,
        anchor_data: Dict[str, Any],
        current_head_hash: str,
        current_sequence_id: int,
        public_key_path: Optional[Union[str, Path]] = None,
        secret_hmac_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Verifies that:
        1. The anchor's signature is valid (using Ed25519 public key or HMAC key).
        2. The anchor's chain_head_hash matches the local database entry at sequence_id.
        """
        signing_type = anchor_data.get("signing_type", "none")
        signature = anchor_data.get("signature", "")
        canonical_payload = cls._canonicalize_anchor_payload(anchor_data)

        # 1. Verify anchor signature
        if signing_type == "ed25519":
            if not public_key_path:
                return (
                    False,
                    "Anchor was signed with Ed25519, but no public key was provided for verification.",
                )
            valid_sig = AsymmetricEngine.verify_payload(
                canonical_payload, signature, public_key_path
            )
            if not valid_sig:
                return (
                    False,
                    "Anchor signature verification failed! The anchor file has been modified or forged.",
                )
        elif signing_type == "hmac_sha256":
            if not secret_hmac_key:
                return (
                    False,
                    "Anchor was signed with HMAC, but no secret key was provided for verification.",
                )
            expected_sig = hmac.new(
                secret_hmac_key.encode("utf-8"), canonical_payload, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return False, "Anchor HMAC signature mismatch! Possible anchor file tampering."

        # 2. Verify chain head consistency
        anchored_seq = anchor_data.get("sequence_id", 0)
        anchored_hash = anchor_data.get("chain_head_hash", "")

        if current_sequence_id == anchored_seq:
            if current_head_hash != anchored_hash:
                return False, (
                    f"AUDIT INTEGRITY VIOLATION: Local chain head hash ({current_head_hash[:16]}...) "
                    f"does not match externally verified anchor hash ({anchored_hash[:16]}...) at sequence #{anchored_seq}!"
                )
        elif current_sequence_id < anchored_seq:
            return False, (
                f"AUDIT TRUNCATION DETECTED: Local audit sequence #{current_sequence_id} is behind "
                f"anchored sequence #{anchored_seq}. Database records may have been deleted!"
            )

        return True, f"Chain-head anchor verified successfully at sequence #{anchored_seq}."
