from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text
from sqlalchemy.sql import func

from app.db.base_class import Base


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(String, primary_key=True, index=True)
    encrypted_data = Column(Text, nullable=False)
    iv = Column(String, nullable=False)
    passphrase_hash = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_accessed = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)


class SecretLog(Base):
    __tablename__ = "secret_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    secret_id = Column(String, index=True)
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    additional_info = Column(Text, nullable=True)
