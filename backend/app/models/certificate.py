from datetime import datetime
from typing import Optional, List
from enum import Enum

from sqlalchemy import Column, Integer, String, Boolean, DateTime, LargeBinary, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class CertificateType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"


class CertificateStatus(str, Enum):
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(SQLEnum(CertificateType), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey("certificates.id"), nullable=True, index=True)
    key_id = Column(Integer, ForeignKey("keys.id"), nullable=True, index=True)
    serial_number = Column(String(64), unique=True, index=True)
    subject_cn = Column(String(255), index=True)
    not_before = Column(DateTime, nullable=False, index=True)
    not_after = Column(DateTime, nullable=False, index=True)
    status = Column(SQLEnum(CertificateStatus), default=CertificateStatus.VALID, index=True)
    certificate_der = Column(LargeBinary, nullable=False)
    meta_data = Column(Text, nullable=False, default="{}")
    revoked_at = Column(DateTime, nullable=True)
    is_deleted = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    parent = relationship("Certificate", remote_side=[id], backref="children")
    key = relationship("Key", back_populates="certificates")
