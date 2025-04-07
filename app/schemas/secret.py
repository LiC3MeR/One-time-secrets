from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class SecretBase(BaseModel):
    pass

class SecretCreate(SecretBase):
    secret: str = Field(..., description="Секретные данные для хранения")
    passphrase: Optional[str] = Field(None, description="Пароль для доступа к секрету")
    ttl_seconds: Optional[int] = Field(None, description="Время жизни секрета в секундах")

class SecretResponse(BaseModel):
    secret_key: str = Field(..., description="Ключ для доступа к секрету")

class SecretShow(BaseModel):
    secret: str = Field(..., description="Расшифрованные секретные данные")

class SecretLog(BaseModel):
    id: str
    secret_id: str
    action: str
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    additional_info: Optional[str] = None

    class Config:
        orm_mode = True