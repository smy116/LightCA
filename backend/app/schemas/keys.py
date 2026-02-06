from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from app.models.key import KeyAlgorithm


class KeyCreateRequest(BaseModel):
    algorithm: KeyAlgorithm = Field(..., description="Key algorithm (RSA, ECDSA, EdDSA)")
    key_size: Optional[int] = Field(
        None, ge=2048, le=4096, description="Key size for RSA (2048 or 4096)"
    )
    curve: Optional[str] = Field(
        None,
        pattern="^(P-256|P-384|Ed25519|Ed448)$",
        description="Curve for ECDSA or EdDSA",
    )
    password: Optional[str] = Field(None, description="Private key password")
    remember_password: bool = Field(False, description="Whether to remember the password")


class KeyImportRequest(BaseModel):
    key_pem: str = Field(..., description="Private key PEM content")
    password: Optional[str] = Field(None, description="Private key password")
    remember_password: bool = Field(False, description="Whether to remember the password")


class KeyDetail(BaseModel):
    id: int
    algorithm: KeyAlgorithm
    fingerprint: str
    is_protected: bool
    meta_data: Dict[str, Any]
    created_at: datetime


class KeyListResponse(BaseModel):
    keys: list[KeyDetail]
    total: int
    page: int
    per_page: int


class KeyExportRequest(BaseModel):
    key_id: int
    format: str = Field(..., pattern="^(pem|pkcs8|pkcs12)$")
    password: Optional[str] = Field(None, description="Password for encrypted export")


class KeyDeleteRequest(BaseModel):
    key_id: int
