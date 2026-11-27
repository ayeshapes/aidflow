import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.session import get_db
from app.schemas.health import HealthOut

logger = logging.getLogger("aidflow")
router = APIRouter()


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)):
    """Proves the whole chain works: API -> database."""
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.exception("Health check: database unreachable")
        raise AppError(503, "DB_UNAVAILABLE", "Database is not reachable")
    return {"status": "ok", "db": True}
