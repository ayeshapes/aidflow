"""AidFlow backend entry point. Every route lives under /api."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.core.config import settings
from app.core.errors import register_error_handlers

app = FastAPI(
    title="AidFlow",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,  # keeps every URL under /api
)

# CORS: only the dev frontend origin, only the methods and headers we use.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

register_error_handlers(app)
app.include_router(api_router)
