from datetime import datetime, timedelta
import hashlib
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.secret import Secret, SecretLog
from app.schemas.secret import SecretCreate, SecretResponse, SecretShow
from app.services.encryption import encrypt_data, decrypt_data
from app.services.cache import get_cache, set_cache, delete_secret_from_cache, set_secret_in_cache
from app.core.config import settings

router = APIRouter()

# Функция для установки заголовков, запрещающих кэширование
def set_no_cache_headers(response: Response):
    if response:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

@router.post("/secret", response_model=SecretResponse)
def create_secret(
    secret_data: SecretCreate,
    request: Request = None,
    response: Response = None,
    db: Session = Depends(get_db)
) -> Any:
    # Устанавливаем заголовки, запрещающие кэширование
    set_no_cache_headers(response)
    
    # Генерируем уникальный идентификатор для секрета
    secret_id = str(uuid.uuid4())
    
    # Шифруем данные
    encrypted_data, iv = encrypt_data(secret_data.secret)
    
    # Хешируем пароль, если он предоставлен
    passphrase_hash = None
    if secret_data.passphrase:
        passphrase_hash = hashlib.sha256(secret_data.passphrase.encode()).hexdigest()
    
    # Определяем время истечения срока действия
    ttl_seconds = secret_data.ttl_seconds or settings.DEFAULT_SECRET_TTL_SECONDS
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    
    # Создаем запись о секрете в базе данных
    db_secret = Secret(
        id=secret_id,
        encrypted_data=encrypted_data,
        iv=iv,
        passphrase_hash=passphrase_hash,
        expires_at=expires_at,
        is_accessed=False,
        is_deleted=False
    )
    
    # Сохраняем секрет в базе данных
    db.add(db_secret)
    
    # Записываем в журнал информацию о создании секрета
    log_entry = SecretLog(
        secret_id=secret_id,
        action="created",
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get("user-agent", "") if request else None,
    )
    db.add(log_entry)
    db.commit()
    
    # Сохраняем информацию о секрете в кэш для быстрого доступа
    cache_data = {
        "created_at": db_secret.created_at.isoformat() if db_secret.created_at else None,
        "expires_at": db_secret.expires_at.isoformat() if db_secret.expires_at else None,
        "has_passphrase": passphrase_hash is not None
    }
    set_secret_in_cache(secret_id, cache_data, ttl_seconds)
    
    # Возвращаем ключ для доступа к секрету
    return {"secret_key": secret_id}

@router.get("/secret/{secret_key}", response_model=SecretShow)
def get_secret(
    secret_key: str,
    passphrase: Optional[str] = None,
    request: Request = None,
    response: Response = None,
    db: Session = Depends(get_db)
) -> Any:
    # Устанавливаем заголовки, запрещающие кэширование
    set_no_cache_headers(response)
    
    # Проверяем, не был ли секрет уже прочитан
    cache_key = f"secret_accessed:{secret_key}"
    if get_cache(cache_key):
        # Записываем в журнал попытку повторного доступа
        log_entry = SecretLog(
            secret_id=secret_key,
            action="access_denied",
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent", "") if request else None,
            additional_info="Secret already accessed"
        )
        db.add(log_entry)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or already accessed"
        )
    
    # Ищем секрет в базе данных
    secret = db.query(Secret).filter(Secret.id == secret_key).first()
    if not secret or secret.is_accessed or secret.is_deleted:
        # Записываем в журнал попытку доступа к несуществующему секрету
        log_entry = SecretLog(
            secret_id=secret_key,
            action="access_denied",
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent", "") if request else None,
            additional_info="Secret not found"
        )
        db.add(log_entry)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or already accessed"
        )
    
    # Проверяем, не истек ли срок действия секрета
    # Преобразуем даты к одному формату (без часового пояса)
    now = datetime.utcnow()
    if secret.expires_at:
        # Если expires_at имеет часовой пояс, преобразуем его к naive datetime
        if hasattr(secret.expires_at, 'tzinfo') and secret.expires_at.tzinfo:
            expires_at = secret.expires_at.replace(tzinfo=None)
        else:
            expires_at = secret.expires_at
            
        if expires_at < now:
            # Помечаем секрет как удаленный
            secret.is_deleted = True
            # Записываем в журнал информацию об истечении срока действия
            log_entry = SecretLog(
                secret_id=secret_key,
                action="expired",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Secret expired"
            )
            db.add(log_entry)
            db.commit()
            # Удаляем информацию о секрете из кэша
            delete_secret_from_cache(secret_key)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret has expired"
            )
    
    # Проверяем пароль, если он требуется
    if secret.passphrase_hash:
        if not passphrase:
            # Записываем в журнал попытку доступа без пароля
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_denied",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Passphrase required but not provided"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Passphrase is required"
            )
        
        # Проверяем правильность пароля
        provided_hash = hashlib.sha256(passphrase.encode()).hexdigest()
        if provided_hash != secret.passphrase_hash:
            # Записываем в журнал попытку доступа с неверным паролем
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_denied",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Incorrect passphrase"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect passphrase"
            )
    
    # Расшифровываем данные секрета
    decrypted_data = decrypt_data(secret.encrypted_data, secret.iv)
    
    # Помечаем секрет как прочитанный
    secret.is_accessed = True
    
    # Записываем в журнал информацию о успешном доступе
    log_entry = SecretLog(
        secret_id=secret_key,
        action="accessed",
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get("user-agent", "") if request else None,
    )
    db.add(log_entry)
    db.commit()
    
    # Помечаем в кэше, что секрет был прочитан
    set_cache(cache_key, "1", 86400)
    
    # Удаляем информацию о секрете из кэша
    delete_secret_from_cache(secret_key)
    
    # Возвращаем расшифрованный секрет
    return {"secret": decrypted_data}


@router.delete("/secret/{secret_key}")
def delete_secret(
    secret_key: str,
    passphrase: Optional[str] = None,
    request: Request = None,
    response: Response = None,
    db: Session = Depends(get_db)
) -> Any:
    # Устанавливаем заголовки, запрещающие кэширование
    set_no_cache_headers(response)
    
    # Ищем секрет в базе данных
    secret = db.query(Secret).filter(Secret.id == secret_key).first()
    if not secret or secret.is_deleted:
        # Записываем в журнал попытку удаления несуществующего секрета
        log_entry = SecretLog(
            secret_id=secret_key,
            action="delete_denied",
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent", "") if request else None,
            additional_info="Secret not found"
        )
        db.add(log_entry)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    # Проверяем, не истек ли срок действия секрета
    now = datetime.utcnow()
    if secret.expires_at:
        # Если expires_at имеет часовой пояс, преобразуем его к naive datetime
        if hasattr(secret.expires_at, 'tzinfo') and secret.expires_at.tzinfo:
            expires_at = secret.expires_at.replace(tzinfo=None)
        else:
            expires_at = secret.expires_at
            
        if expires_at < now:
            # Помечаем секрет как удаленный
            secret.is_deleted = True
            # Записываем в журнал информацию об истечении срока действия
            log_entry = SecretLog(
                secret_id=secret_key,
                action="expired",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Secret expired"
            )
            db.add(log_entry)
            db.commit()
            # Удаляем информацию о секрете из кэша
            delete_secret_from_cache(secret_key)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret has expired"
            )
    
    # Проверяем пароль, если он требуется
    if secret.passphrase_hash:
        if not passphrase:
            # Записываем в журнал попытку удаления без пароля
            log_entry = SecretLog(
                secret_id=secret_key,
                action="delete_denied",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Passphrase required but not provided"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Passphrase is required"
            )
        
        # Проверяем правильность пароля
        provided_hash = hashlib.sha256(passphrase.encode()).hexdigest()
        if provided_hash != secret.passphrase_hash:
            # Записываем в журнал попытку удаления с неверным паролем
            log_entry = SecretLog(
                secret_id=secret_key,
                action="delete_denied",
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent", "") if request else None,
                additional_info="Incorrect passphrase"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect passphrase"
            )
    
    # Помечаем секрет как удаленный
    secret.is_deleted = True
    
    # Записываем в журнал информацию об удалении
    log_entry = SecretLog(
        secret_id=secret_key,
        action="deleted",
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get("user-agent", "") if request else None,
    )
    db.add(log_entry)
    db.commit()
    
    # Удаляем информацию о секрете из кэша
    delete_secret_from_cache(secret_key)
    
    # Возвращаем подтверждение удаления
    return {"status": "secret_deleted"}
