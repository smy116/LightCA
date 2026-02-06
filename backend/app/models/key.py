from datetime import datetime
from enum import Enum

from sqlalchemy import Column, Integer, String, Boolean, Text, ForeignKey, DateTime as SADateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class KeyAlgorithm(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    EdDSA = "EdDSA"


class Key(Base):
    __tablename__ = "keys"
    
    id = Column(Integer, primary_key=True, index=True)
    algorithm = Column(String(16), nullable=False, index=True)
    fingerprint = Column(String(64), unique=True, index=True)
    encrypted_pem = Column(Text, nullable=False)
    is_protected = Column(Boolean, default=False)
    encrypted_password = Column(Text, nullable=True)
    meta_data = Column(Text, nullable=False, default="{}")
    is_deleted = Column(Boolean, default=False, index=True)
    created_at = Column(SADateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    certificates = relationship("Certificate", back_populates="key")
