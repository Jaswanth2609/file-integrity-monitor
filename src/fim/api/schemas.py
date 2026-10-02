"""
REST API Models and Schemas for FIM v2.0.
"""

from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
    HAVE_PYDANTIC = True
except ImportError:
    HAVE_PYDANTIC = False

if HAVE_PYDANTIC:
    class BaselineCreateRequest(BaseModel):
        name: str = Field(..., description="Unique name for the baseline profile")
        paths: List[str] = Field(..., description="List of root directory/file paths to include")
        algo: Optional[str] = Field("sha256", description="Cryptographic hashing algorithm (sha256, sha512, blake2b)")

    class CheckRequest(BaseModel):
        profile: str = Field("default", description="Baseline profile name to verify against")

    class FindingResponse(BaseModel):
        id: Optional[int] = None
        path: str
        change_type: str
        severity: str
        description: str
        old_hash: Optional[str] = None
        new_hash: Optional[str] = None
        attack_id: Optional[str] = None
else:
    # Generic dict fallback
    BaselineCreateRequest = dict  # type: ignore
    CheckRequest = dict  # type: ignore
    FindingResponse = dict  # type: ignore
