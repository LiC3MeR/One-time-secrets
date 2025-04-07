import os
from typing import List, Optional
from pydantic import BaseSettings, validator

class Settings(BaseSettings):
    # Базовые настройки API
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Secret Sharing API"
    BACKEND_CORS_ORIGINS: List[str] = ["*"]
    
    # Настройки базы данных
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "db")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "app")
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    
    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: dict) -> str:
        if v:
            return v
        return f"postgresql://{values.get('POSTGRES_USER')}:{values.get('POSTGRES_PASSWORD')}@{values.get('POSTGRES_SERVER')}/{values.get('POSTGRES_DB')}"
    
    # Настройки Redis
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", None)
    
    # Настройки безопасности
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkey")
    
    # Настройки секретов
    DEFAULT_SECRET_TTL_SECONDS: int = 86400
    
    class Config:
        case_sensitive = True

settings = Settings()