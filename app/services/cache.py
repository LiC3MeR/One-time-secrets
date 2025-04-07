import json
import redis
from datetime import datetime, timedelta

from app.core.config import settings

redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=int(settings.REDIS_PORT),
    db=0,
    decode_responses=True
)


def set_secret_in_cache(secret_key: str, secret_data: dict, ttl_seconds: int = None):
    min_ttl = settings.MIN_CACHE_TIME_SECONDS
    if ttl_seconds is not None:
        ttl_seconds = max(ttl_seconds, min_ttl)
    else:
        ttl_seconds = settings.DEFAULT_SECRET_TTL_SECONDS
    
    redis_client.setex(
        f"secret:{secret_key}",
        ttl_seconds,
        json.dumps(secret_data)
    )


def get_secret_from_cache(secret_key: str) -> dict:
    data = redis_client.get(f"secret:{secret_key}")
    if data:
        return json.loads(data)
    return None


def delete_secret_from_cache(secret_key: str):
    redis_client.delete(f"secret:{secret_key}")
