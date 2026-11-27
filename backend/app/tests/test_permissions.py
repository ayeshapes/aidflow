"""A-02: RBAC driven by the permission matrix (core/permissions.py).

EXPECTED below is a second, independent transcription of the project's access
control matrix. The tests call real HTTP routes and compare what the server
does with this literal, so the table in core/permissions.py cannot drift from
the agreed matrix without a test failing and a reviewer seeing both edits.
"""
import itertools
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import permissions as perm
from app.core.errors import register_error_handlers
from app.core.permissions import require_capability, require_roles
from app.core.security import create_access_token
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import User
from app.tests.matrix_report import RESULTS, ROLE_ORDER

A, W, F, U = "admin", "warehouse", "field", "auditor"

# (matrix row text, capability name, roles with a "Yes"/qualified cell)
EXPECTED = [
    ("Manage users, roles, activation",   "manage_users",                  {A}),
    ("Create/edit donations",             "edit_donations",                {A}),
    ("View donations",                    "view_donations",                {A, W, U}),
    ("Suppliers, purchases, receipt upload", "manage_procurement",         {W}),
    ("View purchases and receipts",       "view_purchases",                {A, W, U}),
    ("Verify receipt hash",               "verify_receipt_hash",           {A, W, U}),
    ("Record stock movements (IN/adjust)", "record_stock_movements",       {W}),
    ("View inventory",                    "view_inventory",                {A, W, F, U}),
    ("Register beneficiary",              "register_beneficiary",          {A, F}),
    ("Assign beneficiary to officer",     "assign_beneficiary",            {A}),
    ("View beneficiary",                  "view_beneficiary",              {A, F, U}),
    ("Create/sign distribution",          "sign_distribution",             {F}),
    ("Verify distribution signature",     "verify_distribution_signature", {A, F, U}),
    ("View/verify audit log",             "view_audit_log",                {A, U}),
    ("Certificates: view",                "view_certificates",             {A, F, U}),
    ("Certificates: revoke",              "revoke_certificates",           {A}),
    ("Backups: create/restore",           "manage_backups",                {A}),
]
CAPABILITIES = [cap for _, cap, _ in EXPECTED]


# ---------- fixtures ----------

@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def tokens(engine):
    """One active user per role, plus a ready-made bearer header for each."""
    out = {}
    with sessionmaker(bind=engine, autoflush=False)() as db:
        for role in ROLE_ORDER:
            # No login happens here, so the hash can be a placeholder (and fast).
            user = User(username=f"{role}-user", password_hash="not-used", role=role, is_active=True)
            db.add(user)
            db.commit()
            token, _ = create_access_token(user.id, user.role)
            out[role] = {"Authorization": f"Bearer {token}"}
    return out


def _override_db(engine):
    def override():
        with sessionmaker(bind=engine, autoflush=False)() as s:
            yield s

    return override


@pytest.fixture(scope="module")
def matrix_client(engine):
    """A throw-away app with one dummy route per capability. It exists only in
    tests, so no real endpoint has to exist yet for every matrix row."""
    test_app = FastAPI()
    register_error_handlers(test_app)

    def make_route(capability):
        def route(user: User = Depends(require_capability(capability))):
            return {"ok": True, "role": user.role}

        return route

    for capability in CAPABILITIES:
        test_app.add_api_route(f"/matrix/{capability}", make_route(capability), methods=["GET"])
    test_app.dependency_overrides[get_db] = _override_db(engine)
    return TestClient(test_app)


@pytest.fixture
def real_client(engine):
    app.dependency_overrides[get_db] = _override_db(engine)
    yield TestClient(app)
    app.dependency_overrides.clear()


# ---------- the matrix: one case per (row, role) ----------

@pytest.mark.parametrize(
    "capability,role",
    [pytest.param(cap, role, id=f"{cap}[{role}]") for cap, role in itertools.product(CAPABILITIES, ROLE_ORDER)],
)
def test_matrix_row(matrix_client, tokens, capability, role):
    row_roles = next(roles for _, cap, roles in EXPECTED if cap == capability)
    expected = 200 if role in row_roles else 403

    response = matrix_client.get(f"/matrix/{capability}", headers=tokens[role])

    RESULTS[(capability, role)] = (response.status_code, expected)
    assert response.status_code == expected, f"{role} on {capability}: {response.text}"
    if expected == 403:
        assert response.json() == {
            "error": {"code": "FORBIDDEN", "message": "You do not have permission to do this"}
        }


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_no_token_is_401_not_403(matrix_client, capability):
    # Authentication comes first: an anonymous caller must not learn about roles.
    assert matrix_client.get(f"/matrix/{capability}").status_code == 401


def test_table_has_exactly_the_matrix_rows_and_roles():
    assert set(perm.PERMISSIONS) == set(CAPABILITIES)
    for _, cap, roles in EXPECTED:
        assert perm.PERMISSIONS[cap] == frozenset(roles), cap


# ---------- a real endpoint, wired through the same table ----------

@pytest.mark.parametrize("role", ROLE_ORDER)
def test_real_users_endpoint_follows_manage_users(real_client, tokens, role):
    status = real_client.get("/api/users", headers=tokens[role]).status_code
    assert status == (200 if role in perm.PERMISSIONS["manage_users"] else 403)


# ---------- dependency behaviour ----------

def test_unknown_capability_fails_when_route_is_defined():
    with pytest.raises(KeyError, match="Unknown capability"):
        require_capability("view_donatoins")  # typo


def test_require_roles_rejects_roles_the_table_does_not_know():
    require_roles("admin")  # fine
    with pytest.raises(ValueError):
        require_roles("superuser")


def test_endpoints_do_not_hard_code_roles():
    """No module under app/api may name a role or call require_roles."""
    api_dir = Path(perm.__file__).resolve().parent.parent / "api"
    role_literal = re.compile(r"""["'](admin|warehouse|field|auditor)["']""")
    offenders = []
    for path in sorted(api_dir.glob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if role_literal.search(line) or "require_roles" in line:
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert not offenders, "use require_capability instead:\n" + "\n".join(offenders)


# ---------- helpers for rules a role check cannot express ----------

def make_user(role, user_id=1):
    return User(id=user_id, username=f"{role}{user_id}", password_hash="x", role=role, is_active=True)


class _TestBase(DeclarativeBase):
    pass


class _Beneficiary(_TestBase):
    """Stand-in for the future Beneficiary model (same column name the helper uses)."""
    __tablename__ = "t_beneficiary"
    id: Mapped[int] = mapped_column(primary_key=True)
    assigned_officer_id: Mapped[int | None] = mapped_column(default=None)


def _ids(db: Session, user):
    stmt = perm.scope_beneficiaries(select(_Beneficiary.id).order_by(_Beneficiary.id), user, _Beneficiary)
    return list(db.scalars(stmt))


def test_field_officer_sees_only_assigned_beneficiaries():
    eng = create_engine("sqlite://")
    _TestBase.metadata.create_all(eng)
    with Session(eng) as db:
        db.add_all([
            _Beneficiary(id=1, assigned_officer_id=7),
            _Beneficiary(id=2, assigned_officer_id=8),
            _Beneficiary(id=3, assigned_officer_id=7),
            _Beneficiary(id=4, assigned_officer_id=None),
        ])
        db.commit()
        assert _ids(db, make_user(F, 7)) == [1, 3]
        assert _ids(db, make_user(F, 8)) == [2]
        assert _ids(db, make_user(F, 99)) == []
        assert _ids(db, make_user(A)) == [1, 2, 3, 4]
        assert _ids(db, make_user(U)) == [1, 2, 3, 4]
        assert _ids(db, make_user(W)) == []  # no capability: fail closed


def test_can_view_beneficiary_single_row():
    mine = SimpleNamespace(assigned_officer_id=7)
    unassigned = SimpleNamespace(assigned_officer_id=None)
    other = SimpleNamespace(assigned_officer_id=8)
    assert perm.can_view_beneficiary(make_user(F, 7), mine)
    assert not perm.can_view_beneficiary(make_user(F, 7), other)
    assert not perm.can_view_beneficiary(make_user(F, 7), unassigned)
    assert perm.can_view_beneficiary(make_user(A), other)
    assert perm.can_view_beneficiary(make_user(U), other)
    assert not perm.can_view_beneficiary(make_user(W), mine)


BENEFICIARY = {"id": 5, "full_name": "Amina Khan", "national_id": "3520212345671",
               "phone": "03001234567", "address": "12 Canal Rd", "district": "Swat"}


def test_admin_sees_masked_values():
    out = perm.redact_beneficiary(make_user(A), BENEFICIARY)
    assert out["national_id"] == "*********5671"
    assert out["phone"] == "*******4567"
    assert out["full_name"] == "******Khan"
    assert out["id"] == 5 and out["district"] == "Swat"  # non-PII untouched


def test_auditor_sees_no_pii_at_all():
    out = perm.redact_beneficiary(make_user(U), BENEFICIARY)
    assert out == {"id": 5, "district": "Swat"}


def test_field_officer_sees_full_values_and_input_is_not_mutated():
    original = dict(BENEFICIARY)
    assert perm.redact_beneficiary(make_user(F), BENEFICIARY) == original
    perm.redact_beneficiary(make_user(A), BENEFICIARY)
    perm.redact_beneficiary(make_user(U), BENEFICIARY)
    assert BENEFICIARY == original


def test_role_without_a_pii_rule_sees_none():
    assert perm.redact_beneficiary(make_user(W), BENEFICIARY) == {"id": 5, "district": "Swat"}


def test_mask_value_edge_cases():
    assert perm.mask_value("12") == "**"
    assert perm.mask_value("12345") == "*2345"
    assert perm.mask_value("") == ""
    assert perm.mask_value(None) is None


def test_officer_creates_and_signs_only_own_distributions():
    mine = SimpleNamespace(officer_id=7)
    theirs = SimpleNamespace(officer_id=8)
    assert perm.can_sign_distribution(make_user(F, 7), mine)
    assert not perm.can_sign_distribution(make_user(F, 7), theirs)
    for role in (A, W, U):  # no capability at all, even for a row they "own"
        assert not perm.can_sign_distribution(make_user(role, 7), mine)
