"""All routers are mounted here under the /api prefix."""
from fastapi import APIRouter

from app.api import auth, health, users

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
