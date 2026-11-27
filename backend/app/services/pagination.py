"""Pagination helper for list endpoints (?page=&page_size=)."""
from fastapi import Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session


class PageParams:
    """Reads and validates ?page= and ?page_size=. Use: params: PageParams = Depends()"""

    def __init__(
        self,
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        self.page = page
        self.page_size = page_size


def paginate(db: Session, stmt, page: int, page_size: int) -> dict:
    """Run a select() one page at a time.

    The statement MUST have an order_by(), or the pages are not stable.
    """
    # Count all matching rows (ordering is irrelevant for counting).
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
    offset = (page - 1) * page_size
    items = db.scalars(stmt.limit(page_size).offset(offset)).all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}
