"""Response shape for every list endpoint: {items, total, page, page_size}.

Use it as response_model=Page[SomeSchema]. SomeSchema needs
model_config = ConfigDict(from_attributes=True) so it can read database objects.
"""
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
