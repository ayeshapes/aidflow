"""Every kind of error must use {"error": {"code", "message"}}."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError, register_error_handlers
from app.main import app as real_app

# A tiny app that has the handlers plus routes that fail on purpose.
mini = FastAPI()
register_error_handlers(mini)


class Item(BaseModel):
    name: str
    quantity: int


@mini.get("/app-error")
def raise_app_error():
    raise AppError(409, "STOCK_TOO_LOW", "Not enough stock")


@mini.get("/crash")
def crash():
    raise RuntimeError("secret internal detail: db password is hunter2")


@mini.post("/items")
def create_item(item: Item):
    return item


# raise_server_exceptions=False: behave like a real server, return the 500 response.
client = TestClient(mini, raise_server_exceptions=False)


def assert_standard_shape(body, code):
    assert list(body.keys()) == ["error"]
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str)


def test_app_error_uses_its_status_and_code():
    response = client.get("/app-error")
    assert response.status_code == 409
    assert response.json() == {"error": {"code": "STOCK_TOO_LOW", "message": "Not enough stock"}}


def test_unknown_route_is_404():
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert_standard_shape(response.json(), "NOT_FOUND")


def test_wrong_method_is_405():
    response = client.delete("/app-error")
    assert response.status_code == 405
    assert_standard_shape(response.json(), "METHOD_NOT_ALLOWED")


def test_validation_error_is_422_and_does_not_echo_input():
    response = client.post("/items", json={"name": "rice", "quantity": "SECRET-VALUE"})
    assert response.status_code == 422
    assert_standard_shape(response.json(), "VALIDATION_ERROR")
    assert "quantity" in response.json()["error"]["message"]
    assert "SECRET-VALUE" not in response.text


def test_unhandled_exception_is_generic_500_without_details():
    response = client.get("/crash")
    assert response.status_code == 500
    assert response.json() == {"error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}}
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text


def test_real_app_also_uses_standard_shape():
    response = TestClient(real_app).get("/api/nope")
    assert response.status_code == 404
    assert_standard_shape(response.json(), "NOT_FOUND")
