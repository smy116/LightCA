from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime as SADateTime
from sqlalchemy.sql import func

from app.database import Base


class Template(Base):
    __tablename__ = "templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    template_type = Column(String(64), nullable=False, index=True)
    key_usage = Column(Text, nullable=False, default="{}")
    extended_key_usage = Column(Text, nullable=False, default="{}")
    policy = Column(Text, nullable=False, default="{}")
    is_builtin = Column(Boolean, default=False, index=True)
    created_at = Column(SADateTime, server_default=func.now(), nullable=False)
    updated_at = Column(SADateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
