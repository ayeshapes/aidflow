"""Parent class for all database models (models/ will inherit from Base)."""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
