from datetime import datetime

from sqlalchemy import Column, Integer, ForeignKey, LargeBinary, DateTime as SADateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class CRL(Base):
    __tablename__ = "crls"
    
    id = Column(Integer, primary_key=True, index=True)
    ca_id = Column(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    crl_number = Column(Integer, nullable=False, index=True)
    crl_der = Column(LargeBinary, nullable=False)
    generated_at = Column(SADateTime, server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    ca = relationship("Certificate", backref="crls")
