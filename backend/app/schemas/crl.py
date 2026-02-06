from typing import List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class CRLGenerateRequest(BaseModel):
    ca_id: int = Field(..., description="ID of the CA certificate")


class CRLDetail(BaseModel):
    id: int
    ca_id: int
    crl_number: int
    generated_at: datetime


class CRLListResponse(BaseModel):
    crls: list[CRLDetail]
    total: int
    page: int
    per_page: int


class RevocationRecord(BaseModel):
    certificate_id: int
    serial_number: str
    subject_cn: str
    revoked_at: datetime
    reason: str


class CRLRevocationsResponse(BaseModel):
    revocations: list[RevocationRecord]
    total: int
