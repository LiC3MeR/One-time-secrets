import uuid
import time
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.secret import Secret, SecretLog
from app.schemas.secret import SecretCreate, SecretResponse, SecretContent, SecretStatus
from app.services.encryption import encrypt_secret, decrypt_secret, hash_passphrase
from app.services.cache import set_secret_in_cache, get_secret_from_cache, delete_secret_from_cache
from app.core.config import settings

router = APIRouter()


def set_no_cache_headers(response: Response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


@router.post("/secret", response_model=SecretResponse)
async def create_secret(
    secret_data: SecretCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    set_no_cache_headers(response)
    secret_key = str(uuid.uuid4())
    encrypted_data, iv = encrypt_secret(secret_data.secret, secret_data.passphrase)
    
    ttl_seconds = secret_data.ttl_seconds or settings.DEFAULT_SECRET_TTL_SECONDS
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    
    passphrase_hash = None
    if secret_data.passphrase:
        passphrase_hash = hash_passphrase(secret_data.passphrase)
    
    db_secret = Secret(
        id=secret_key,
        encrypted_data=encrypted_data,
        iv=iv,
        passphrase_hash=passphrase_hash,
        expires_at=expires_at
    )
    
    db.add(db_secret)
    
    log_entry = SecretLog(
        secret_id=secret_key,
        action="create",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        additional_info=f"ttl_seconds: {ttl_seconds}"
    )
    db.add(log_entry)
    db.commit()
    
    cache_data = {
        "encrypted_data": encrypted_data,
        "iv": iv,
        "passphrase_hash": passphrase_hash,
        "expires_at": expires_at.timestamp(),
        "is_accessed": False,
        "is_deleted": False
    }
    set_secret_in_cache(secret_key, cache_data, ttl_seconds)
    
    return {"secret_key": secret_key}


@router.get("/secret/{secret_key}", response_model=SecretContent)
async def get_secret(
    secret_key: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    set_no_cache_headers(response)
    
    secret_data = get_secret_from_cache(secret_key)
    
    if not secret_data:
        db_secret = db.query(Secret).filter(Secret.id == secret_key).first()
        if not db_secret:
            raise HTTPException(status_code=404, detail="Secret not found")
        
        if db_secret.expires_at and db_secret.expires_at < datetime.utcnow():
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_expired",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(status_code=404, detail="Secret has expired")
        
        if db_secret.is_accessed or db_secret.is_deleted:
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_unavailable",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent"),
                additional_info="Secret already accessed or deleted"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(status_code=404, detail="Secret not available")
        
        secret_data = {
            "encrypted_data": db_secret.encrypted_data,
            "iv": db_secret.iv,
            "passphrase_hash": db_secret.passphrase_hash,
            "expires_at": db_secret.expires_at.timestamp() if db_secret.expires_at else None,
            "is_accessed": db_secret.is_accessed,
            "is_deleted": db_secret.is_deleted
        }
    else:
        if secret_data.get("expires_at") and secret_data["expires_at"] < time.time():
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_expired",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(log_entry)
            db.commit()
            
            delete_secret_from_cache(secret_key)
            
            raise HTTPException(status_code=404, detail="Secret has expired")
        
        if secret_data.get("is_accessed") or secret_data.get("is_deleted"):
            log_entry = SecretLog(
                secret_id=secret_key,
                action="access_unavailable",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent"),
                additional_info="Secret already accessed or deleted"
            )
            db.add(log_entry)
            db.commit()
            
            raise HTTPException(status_code=404, detail="Secret not available")
    
    db_secret = db.query(Secret).filter(Secret.id == secret_key).first()
    if db_secret:
        db_secret.is_accessed = True
        
        log_entry = SecretLog(
            secret_id=secret_key,
            action="access",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        db.add(log_entry)
        db.commit()
    
    if secret_data:
        secret_data["is_accessed"] = True
        expires_in = secret_data.get("expires_at", time.time() + 3600) - time.time()
        if expires_in > 0:
            set_secret_in_cache(secret_key, secret_data, int(expires_in))
    
    decrypted_secret = decrypt_secret(
        secret_data["encrypted_data"],
        secret_data["iv"]
    )
    
    return {"secret": decrypted_secret}


@router.delete("/secret/{secret_key}", response_model=SecretStatus)
async def delete_secret(
    secret_key: str,
    request: Request,
    response: Response,
    passphrase: Optional[str] = None,
    db: Session = Depends(get_db)
):
    set_no_cache_headers(response)
    secret_data = get_secret_from_cache(secret_key)
    
    if not secret_data:
        db_secret = db.query(Secret).filter(Secret.id == secret_key).first()
        if not db_secret:
            raise HTTPException(status_code=404, detail="Secret not found")
        
        if db_secret.expires_at and db_secret.expires_at < datetime.utcnow():
            log_entry = SecretLog(
                secret_id=secret_key,
                action="delete_expired",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(log_entry)
            db.commit()
            
            raise HTTPException(status_code=404, detail="Secret has expired")
        
        if db_secret.passphrase_hash:
            if not passphrase:
                raise HTTPException(status_code=401, detail="Passphrase required")
            
            if hash_passphrase(passphrase) != db_secret.passphrase_hash:
                log_entry = SecretLog(
                    secret_id=secret_key,
                    action="delete_failed",
                    ip_address=request.client.host,
                    user_agent=request.headers.get("user-agent"),
                    additional_info="Invalid passphrase"
                )
                db.add(log_entry)
                db.commit()
                
                raise HTTPException(status_code=401, detail="Invalid passphrase")

        db_secret.is_deleted = True
        
        log_entry = SecretLog(
            secret_id=secret_key,
            action="delete",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        db.add(log_entry)
        db.commit()
    else:
        if secret_data.get("expires_at") and secret_data["expires_at"] < time.time():
            log_entry = SecretLog(
                secret_id=secret_key,
                action="delete_expired",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(log_entry)
            db.commit()
            
            delete_secret_from_cache(secret_key)
            
            raise HTTPException(status_code=404, detail="Secret has expired")
        
        if secret_data.get("passphrase_hash"):
            if not passphrase:
                raise HTTPException(status_code=401, detail="Passphrase required")
            
            if hash_passphrase(passphrase) != secret_data["passphrase_hash"]:
                log_entry = SecretLog(
                    secret_id=secret_key,
                    action="delete_failed",
                    ip_address=request.client.host,
                    user_agent=request.headers.get("user-agent"),
                    additional_info="Invalid passphrase"
                )
                db.add(log_entry)
                db.commit()
                
                raise HTTPException(status_code=401, detail="Invalid passphrase")
        
        db_secret = db.query(Secret).filter(Secret.id == secret_key).first()
        if db_secret:
            db_secret.is_deleted = True
            
            log_entry = SecretLog(
                secret_id=secret_key,
                action="delete",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(log_entry)
            db.commit()
    
    delete_secret_from_cache(secret_key)
    
    return {"status": "secret_deleted"}
