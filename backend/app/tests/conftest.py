"""Test setup. Runs BEFORE the app is imported, so settings can load.

Inside Docker these variables already exist (from .env) and are kept.
Outside Docker, harmless fake values are used and the DB is in-memory SQLite.
"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
# 32+ bytes: shorter HMAC keys trigger a PyJWT warning.
os.environ.setdefault("JWT_SECRET", "test-only-secret-test-only-secret-0123456789")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-only-key")
os.environ.setdefault("BACKUP_KEY", "test-only-key")


import pytest  # noqa: E402  (after the env defaults above, like every import that needs settings)


@pytest.fixture(autouse=True)
def _fresh_login_rate_limiter():
    """The login limiter is process-wide state. Tests log in as the same user
    from the same fake IP all the time, so start each test with it empty."""
    from app.core.rate_limit import login_limiter

    login_limiter.reset()
    yield


def pytest_terminal_summary(terminalreporter):
    """Print the permission-matrix results table (see matrix_report.py)."""
    from app.tests import matrix_report

    if not matrix_report.RESULTS:
        return
    terminalreporter.section("RBAC matrix: observed HTTP status per role")
    for line in matrix_report.render():
        terminalreporter.write_line(line)
