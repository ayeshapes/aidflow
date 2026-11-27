"""A-04 / SEC-01: every protected route answers 401 to an unauthenticated caller.

The routes are NOT listed by hand. They are read from app.routes, so a route
added in a future ticket is covered the moment it exists. The rule is
DENY BY DEFAULT: a route is protected unless it is on PUBLIC_ROUTES below.
A new route that forgets its auth dependency therefore fails this test; to
make a route public on purpose, add it to PUBLIC_ROUTES in the same pull
request, where a reviewer will see it.
"""
import re

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.errors import register_error_handlers
from app.core.permissions import get_current_user
from app.db.base import Base
from app.db.session import get_db
from app.main import app

# ---------------------------------------------------------------------------
# The ONLY routes that may be called without credentials: (method, path).
# ---------------------------------------------------------------------------
PUBLIC_ROUTES = {
    ("GET", "/api/health"),                  # liveness check, used by the frontend and Docker
    ("POST", "/api/auth/login"),             # this is how a caller GETS credentials
    # Swagger UI and the OpenAPI document. Starlette adds HEAD to these itself.
    ("GET", "/api/docs"), ("HEAD", "/api/docs"),
    ("GET", "/api/openapi.json"), ("HEAD", "/api/openapi.json"),
    ("GET", "/docs/oauth2-redirect"), ("HEAD", "/docs/oauth2-redirect"),
}

# What "no credentials" means. The second row is a token that is present but
# worthless: it must be refused exactly like a missing one.
UNAUTHENTICATED = {
    "no-credentials": {},
    "garbage-bearer-token": {"Authorization": "Bearer not.a.real-token"},
}

EXPECTED_401 = {"error": {"code": "UNAUTHORIZED", "message": "Not authenticated"}}


# ---------------------------------------------------------------------------
# Route enumeration
# ---------------------------------------------------------------------------
def enumerate_routes(routes) -> set[tuple[str, str]]:
    """Return {(METHOD, path_template)} for every route in `routes`.

    Handles both shapes FastAPI uses: a flat list of routes (older versions)
    and lazily-included routers (newer versions, where app.routes holds a
    wrapper that is expanded with effective_route_contexts()). Anything it does
    not recognise (Mount, WebSocket, a future type) FAILS the test instead of
    being skipped, so coverage can never shrink silently.
    """
    found: set[tuple[str, str]] = set()
    for route in routes:
        if hasattr(route, "effective_route_contexts"):
            found |= enumerate_routes(route.effective_route_contexts())
            continue
        path, methods = getattr(route, "path", None), getattr(route, "methods", None)
        if not path or not methods:
            pytest.fail(
                f"SEC-01 cannot test {type(route).__name__} {route!r}: it has no path/methods. "
                "Teach enumerate_routes about it (mounts and websockets need their own auth tests)."
            )
        found |= {(m, path) for m in methods}
    return found


def concrete(path_template: str) -> str:
    """'/api/users/{user_id}/role' -> '/api/users/1/role'.
    Authentication runs before the path value is looked at, so any value does."""
    return re.sub(r"\{[^}]+\}", "1", path_template)


def labelled(pairs):
    return [pytest.param(m, p, id=f"{m} {p}") for m, p in sorted(pairs, key=lambda x: (x[1], x[0]))]


ALL_ROUTES = enumerate_routes(app.routes)
PROTECTED_ROUTES = ALL_ROUTES - PUBLIC_ROUTES


def _in_memory_db():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="module")
def anon_client():
    """The real app with a throw-away database. Nothing here logs in."""
    engine = _in_memory_db()

    def override():
        with sessionmaker(bind=engine, autoflush=False)() as s:
            yield s

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()
    engine.dispose()


# ---------------------------------------------------------------------------
# SEC-01
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("credentials", UNAUTHENTICATED.values(), ids=UNAUTHENTICATED.keys())
@pytest.mark.parametrize("method,path", labelled(PROTECTED_ROUTES))
def test_sec01_protected_route_returns_401_without_credentials(anon_client, method, path, credentials):
    response = anon_client.request(method, concrete(path), headers=credentials)
    assert response.status_code == 401, (
        f"{method} {path} answered {response.status_code} to an unauthenticated request. "
        "Add Depends(get_current_user) or Depends(require_capability(...)), or, if it is "
        "meant to be public, add it to PUBLIC_ROUTES."
    )
    if method != "HEAD":  # a HEAD response has no body
        assert response.json() == EXPECTED_401
    assert response.headers["www-authenticate"] == "Bearer"


# ---------------------------------------------------------------------------
# Guards on the test itself: it must not pass by seeing nothing.
# ---------------------------------------------------------------------------
def test_sec01_every_openapi_operation_was_enumerated():
    """app.openapi() is an independent list of the routes. If it knows a route
    that enumerate_routes() missed, the enumerator is broken."""
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    documented = {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        for method in item if method in http_methods
    }
    assert documented, "OpenAPI lists no routes: the app did not load as expected"
    assert documented <= ALL_ROUTES, f"enumeration missed: {sorted(documented - ALL_ROUTES)}"


def test_sec01_the_protected_set_is_not_empty_and_has_the_known_routes():
    assert len(PROTECTED_ROUTES) >= 8
    for known in [("GET", "/api/auth/me"), ("POST", "/api/auth/logout"),
                  ("GET", "/api/users"), ("PATCH", "/api/users/{user_id}/role")]:
        assert known in PROTECTED_ROUTES


def test_sec01_public_allowlist_has_no_stale_entries():
    """A route that was renamed or removed must not leave a hole behind in the allowlist."""
    assert PUBLIC_ROUTES <= ALL_ROUTES, f"not real routes: {sorted(PUBLIC_ROUTES - ALL_ROUTES)}"


def test_sec01_checker_catches_an_unprotected_route():
    """Build an app with one open route (one of them in a nested router) and
    confirm the same enumeration + probe flags exactly those."""
    mini = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    register_error_handlers(mini)
    engine = _in_memory_db()

    def override():
        with sessionmaker(bind=engine)() as s:
            yield s

    mini.dependency_overrides[get_db] = override

    @mini.get("/closed")
    def closed(_=Depends(get_current_user)):
        return {}

    @mini.get("/open")  # the mistake: no auth dependency
    def open_():
        return {}

    nested = APIRouter(prefix="/v2")

    @nested.delete("/things/{thing_id}")  # the same mistake, behind a prefix
    def forgotten(thing_id: int):
        return {}

    mini.include_router(nested)

    routes = enumerate_routes(mini.routes)
    assert routes == {("GET", "/closed"), ("GET", "/open"), ("DELETE", "/v2/things/{thing_id}")}

    probe = TestClient(mini)
    leaks = sorted(f"{m} {p}" for m, p in routes if probe.request(m, concrete(p)).status_code != 401)
    assert leaks == ["DELETE /v2/things/{thing_id}", "GET /open"]


def test_sec01_enumerator_fails_loudly_on_a_route_it_cannot_test():
    from starlette.routing import Mount

    mini = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mini.mount("/static", FastAPI())
    assert any(isinstance(r, Mount) for r in mini.routes)
    with pytest.raises(pytest.fail.Exception, match="cannot test"):
        enumerate_routes(mini.routes)
