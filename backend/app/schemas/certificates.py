from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, model_validator

from app.models.certificate import CertificateType, CertificateStatus


class CertificateSignRequest(BaseModel):
    type: Optional[str] = Field(
        None, description="Certificate type: 'root', 'intermediate', or 'leaf'"
    )
    issuer_id: int = Field(
        0, description="ID of the issuer CA certificate (0 for self-signed root)"
    )
    key_id: Optional[int] = Field(
        None, description="Key ID for self-signed root CA (required when issuer_id is 0)"
    )
    is_ca: bool = Field(False, description="Whether this is a CA certificate")
    subject: Optional[Dict[str, str]] = Field(None, description="Subject DN (e.g., CN, O, OU, C)")
    subject_dn: Optional[str] = Field(
        None,
        description="Subject DN as string (alternative to subject, format: CN=...,O=...,C=...)",
    )
    key_config: Optional[Dict[str, Any]] = Field(None, description="Key generation configuration")
    validity_days: int = Field(365, ge=1, le=36500, description="Certificate validity in days")
    extensions: Optional[Dict[str, Any]] = Field(None, description="Certificate extensions")
    csr_pem: Optional[str] = Field(None, description="CSR PEM content if signing a CSR")
    parent_id: Optional[int] = Field(
        None, description="Parent certificate ID (alternative to issuer_id)"
    )

    @model_validator(mode="after")
    def parse_and_validate(self):
        """Parse subject_dn and validate type-based mappings."""
        # Parse subject_dn string into subject dict if provided
        if self.subject is None and self.subject_dn:
            subject_dict = {}
            for part in self.subject_dn.split(","):
                part = part.strip()
                if "=" in part:
                    key, value = part.split("=", 1)
                    subject_dict[key.strip()] = value.strip()
            self.subject = subject_dict

        # Map type field to issuer_id and is_ca
        if self.type == "root":
            self.issuer_id = 0
            self.is_ca = True
        elif self.type == "intermediate":
            self.is_ca = True
        elif self.type == "leaf":
            self.is_ca = False

        # Map parent_id to issuer_id if provided
        if self.parent_id is not None:
            self.issuer_id = self.parent_id

        # Validate self-signed root CA key source
        if self.issuer_id == 0 and self.key_id is None and not self.key_config:
            raise ValueError(
                "key_id or key_config is required when creating self-signed root CA (type='root' or issuer_id=0)"
            )

        return self


class CertificateImportRequest(BaseModel):
    cert_pem: str = Field(..., description="Certificate PEM content")
    key_pem: Optional[str] = Field(None, description="Private key PEM content")
    key_password: Optional[str] = Field(None, description="Private key password")
    remember_password: bool = Field(False, description="Whether to remember the password")


class CertificateDetail(BaseModel):
    id: int
    type: CertificateType
    parent_id: Optional[int]
    key_id: Optional[int]
    serial_number: str
    subject_cn: str
    not_before: datetime
    not_after: datetime
    status: CertificateStatus
    meta_data: Dict[str, Any]
    revoked_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class CertificateListResponse(BaseModel):
    certificates: list[CertificateDetail]
    total: int
    page: int
    per_page: int


class CertificateExportRequest(BaseModel):
    certificate_id: int
    format: str = Field(..., pattern="^(pem|der|p12|pem-chain|pem-bundle)$")
    password: Optional[str] = Field(None, description="Password for encrypted export")


class CertificateChainResponse(BaseModel):
    chain: list[Dict[str, Any]]


class CertificateTreeResponse(BaseModel):
    tree: Dict[str, Any]


class CertificateDeleteRequest(BaseModel):
    certificate_id: int
    delete_key: bool = Field(False, description="Whether to delete associated key")


class CertificateRevokeRequest(BaseModel):
    certificate_id: int
    reason: str = Field(..., min_length=1)
    issuer_password: Optional[str] = Field(None, description="Issuer private key password")
