from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.db.session import get_db
from app.main import app

client = TestClient(app)


def test_health_ok():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": True}


def test_health_returns_standard_error_when_db_is_down():
    class BrokenSession:
        def execute(self, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("password=hunter2"))

        def close(self):
            pass

    app.dependency_overrides[get_db] = lambda: BrokenSession()
    try:
        response = client.get("/api/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "DB_UNAVAILABLE", "message": "Database is not reachable"}
    }
    assert "hunter2" not in response.text  # internal details must not leak


def test_docs_and_openapi_live_under_api():
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/docs").status_code == 200
    assert client.get("/docs").status_code == 404
