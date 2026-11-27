import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

from app.core.errors import register_error_handlers
from app.schemas.pagination import Page
from app.services.pagination import PageParams, paginate


# A throw-away table, separate from the real Base so migrations never see it.
class _Base(DeclarativeBase):
    pass


class Thing(_Base):
    __tablename__ = "things"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]


class ThingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


@pytest.fixture
def db():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    _Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([Thing(name=f"thing-{i}") for i in range(1, 26)])  # 25 rows
        session.commit()
        yield session


def query():
    return select(Thing).order_by(Thing.id)


def test_first_page(db):
    result = paginate(db, query(), page=1, page_size=10)
    assert result["total"] == 25
    assert (result["page"], result["page_size"]) == (1, 10)
    assert [t.id for t in result["items"]] == list(range(1, 11))


def test_last_page_is_partial(db):
    result = paginate(db, query(), page=3, page_size=10)
    assert [t.id for t in result["items"]] == [21, 22, 23, 24, 25]
    assert result["total"] == 25


def test_page_past_the_end_is_empty_but_total_is_correct(db):
    result = paginate(db, query(), page=99, page_size=10)
    assert result["items"] == []
    assert result["total"] == 25


def test_filtered_query_counts_only_matches(db):
    stmt = select(Thing).where(Thing.id <= 7).order_by(Thing.id)
    result = paginate(db, stmt, page=1, page_size=5)
    assert result["total"] == 7
    assert len(result["items"]) == 5


def test_result_fits_the_page_schema(db):
    page = Page[ThingOut].model_validate(paginate(db, query(), page=1, page_size=2))
    assert page.model_dump() == {
        "items": [{"id": 1, "name": "thing-1"}, {"id": 2, "name": "thing-2"}],
        "total": 25,
        "page": 1,
        "page_size": 2,
    }


# ---- ?page= and ?page_size= validation, through a tiny app ----
mini = FastAPI()
register_error_handlers(mini)


@mini.get("/echo")
def echo(params: PageParams = Depends()):
    return {"page": params.page, "page_size": params.page_size}


client = TestClient(mini)


def test_defaults():
    assert client.get("/echo").json() == {"page": 1, "page_size": 20}


@pytest.mark.parametrize("qs", ["page=0", "page=-1", "page_size=0", "page_size=101", "page=abc"])
def test_bad_values_give_422_in_standard_shape(qs):
    response = client.get(f"/echo?{qs}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
