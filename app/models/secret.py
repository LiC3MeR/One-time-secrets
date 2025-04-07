from datetime import datetime
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.db.base_class import Base

class Secret(Base):
    __tablename__ = "secrets"

    id = Column(String, primary_key=True, index=True)
    encrypted_data = Column(Text, nullable=False)
    iv = Column(String, nullable=False)
    passphrase_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_accessed = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    
    logs = relationship("SecretLog", back_populates="secret")

class SecretLog(Base):
    __tablename__ = "secret_logs"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    secret_id = Column(String, ForeignKey("secrets.id"))
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    additional_info = Column(Text, nullable=True)
    
    secret = relationship("Secret", back_populates="logs")
    secret = relationship("Secret", back_populates="logs")