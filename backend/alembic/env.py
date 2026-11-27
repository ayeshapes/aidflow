"""Alembic environment. Uses the same DATABASE_URL and models as the app."""
from alembic import context
from sqlalchemy import create_engine

from app.core.config import settings
from app.db.base import Base
import app.models  # noqa: F401  (registers every table on Base.metadata)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    engine = create_engine(settings.database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
