from fastapi import APIRouter

from app.api.endpoints import secrets

api_router = APIRouter()
api_router.include_router(secrets.router, prefix="", tags=["secrets"])
