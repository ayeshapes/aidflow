"""Import every model here so Base.metadata (used by Alembic and tests) sees them."""
from app.models.token_denylist import TokenDenylist
from app.models.user import Role, User

__all__ = ["Role", "TokenDenylist", "User"]
