import json
import redis
from typing import Any, Dict, Optional

from app.core.config import settings

redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True
)

def get_cache(key: str) -> Optional[str]:
    try:
        return redis_client.get(key)
    except Exception as e:
        print(f"Error getting cache: {e}")
        return None

def set_cache(key: str, value: str, ttl: int = 3600) -> bool:
    try:
        redis_client.set(key, value, ex=ttl)
        return True
    except Exception as e:
        print(f"Error setting cache: {e}")
        return False

def delete_cache(key: str) -> bool:
    try:
        redis_client.delete(key)
        return True
    except Exception as e:
        print(f"Error deleting cache: {e}")
        return False

def get_secret_from_cache(secret_id: str) -> Optional[Dict[str, Any]]:
    cache_key = f"secret:{secret_id}"
    cache_data = get_cache(cache_key)
    if cache_data:
        try:
            return json.loads(cache_data)
        except json.JSONDecodeError:
            return None
    return None

def set_secret_in_cache(secret_id: str, data: Dict[str, Any], ttl: int = 3600) -> bool:
    cache_key = f"secret:{secret_id}"
    try:
        cache_data = json.dumps(data)
        return set_cache(cache_key, cache_data, ttl)
    except Exception as e:
        print(f"Error setting secret in cache: {e}")
        return False

def delete_secret_from_cache(secret_id: str) -> bool:
    cache_key = f"secret:{secret_id}"
    return delete_cache(cache_key)