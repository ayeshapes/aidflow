"""CORS must allow the dev frontend origin and nobody else."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
DEV = "http://localhost:5173"


def test_dev_origin_is_allowed():
    response = client.get("/api/health", headers={"Origin": DEV})
    assert response.headers["access-control-allow-origin"] == DEV


def test_other_origin_is_not_allowed():
    response = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_preflight_from_dev_origin_allows_authorization_header():
    response = client.options(
        "/api/health",
        headers={
            "Origin": DEV,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert response.status_code == 200
    assert "authorization" in response.headers["access-control-allow-headers"].lower()


def test_preflight_from_other_origin_is_refused():
    response = client.options(
        "/api/health",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 400
