from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class SecretCreate(BaseModel):
    secret: str
    passphrase: Optional[str] = None
    ttl_seconds: Optional[int] = None


class SecretResponse(BaseModel):
    secret_key: str


class SecretContent(BaseModel):
    secret: str


class SecretStatus(BaseModel):
    status: str


class SecretLog(BaseModel):
    id: int
    secret_id: str
    action: str
    ip_address: Optional[str]
    timestamp: datetime
    
    class Config:
        orm_mode = True
