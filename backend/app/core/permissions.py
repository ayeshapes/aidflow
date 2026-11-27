"""WHO CAN DO WHAT: the single source of truth for authorization.

Read PERMISSIONS below to audit the whole system. Every row is one line of the
access-control matrix (capability -> roles that hold it). Nothing else in the
code base decides access by role name: endpoints ask for a capability, e.g.
`Depends(require_capability("view_donations"))`, and this file answers.

The file has four parts:
  1. PERMISSIONS        the table (capability -> set of roles)
  2. QUALIFIERS         the "own only" / "masked" / "no PII" notes in matrix cells
  3. authentication     get_current_user (401), require_capability and
                        require_roles (403), both reading the table
  4. scope helpers      small functions for rules a role check cannot express
"""
from typing import Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import false
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import Role, TokenDenylist, User

ADMIN = Role.admin.value
WAREHOUSE = Role.warehouse.value
FIELD = Role.field.value
AUDITOR = Role.auditor.value

# ---------------------------------------------------------------------------
# 1. THE TABLE. One row per row of the access-control matrix.
#    To change who can do what, edit this table and the expected matrix in
#    app/tests/test_permissions.py in the same pull request.
# ---------------------------------------------------------------------------
PERMISSIONS: dict[str, frozenset[str]] = {
    # capability (matrix row)         roles that hold it
    "manage_users":                   frozenset({ADMIN}),  # users, roles, activation
    "edit_donations":                 frozenset({ADMIN}),  # create / edit donations
    "view_donations":                 frozenset({ADMIN, WAREHOUSE, AUDITOR}),
    "manage_procurement":             frozenset({WAREHOUSE}),  # suppliers, purchases, receipt upload
    "view_purchases":                 frozenset({ADMIN, WAREHOUSE, AUDITOR}),  # purchases + receipts
    "verify_receipt_hash":            frozenset({ADMIN, WAREHOUSE, AUDITOR}),
    "record_stock_movements":         frozenset({WAREHOUSE}),  # IN / adjust
    "view_inventory":                 frozenset({ADMIN, WAREHOUSE, FIELD, AUDITOR}),  # field: read only
    "register_beneficiary":           frozenset({ADMIN, FIELD}),
    "assign_beneficiary":             frozenset({ADMIN}),  # assign to a field officer
    "view_beneficiary":               frozenset({ADMIN, FIELD, AUDITOR}),  # see QUALIFIERS
    "sign_distribution":              frozenset({FIELD}),  # create / sign; own only
    "verify_distribution_signature":  frozenset({ADMIN, FIELD, AUDITOR}),
    "view_audit_log":                 frozenset({ADMIN, AUDITOR}),  # view / verify
    "view_certificates":              frozenset({ADMIN, FIELD, AUDITOR}),  # field: own only
    "revoke_certificates":            frozenset({ADMIN}),
    "manage_backups":                 frozenset({ADMIN}),  # create / restore
}

# ---------------------------------------------------------------------------
# 2. QUALIFIERS: the notes inside matrix cells ("Own", "Masked", "No PII").
#    Holding a capability is necessary; these narrow WHAT the holder may touch.
# ---------------------------------------------------------------------------
# Roles that only get their OWN rows for a capability (helpers below apply it).
OWN_ONLY: dict[str, frozenset[str]] = {
    "view_beneficiary": frozenset({FIELD}),   # "Own assigned only"
    "sign_distribution": frozenset({FIELD}),  # "Yes (own)"
    "view_certificates": frozenset({FIELD}),  # "Own"
}

# How much beneficiary PII each role sees: full, masked, or none.
# A role missing from this table sees none (fail closed).
FULL, MASKED, NONE = "full", "masked", "none"
BENEFICIARY_PII: dict[str, str] = {
    ADMIN: MASKED,    # "Masked"
    FIELD: FULL,      # works with their own assigned people
    AUDITOR: NONE,    # "No PII"
}
# Beneficiary fields that count as PII. Extend when the beneficiary schema lands.
BENEFICIARY_PII_FIELDS = frozenset({"full_name", "national_id", "phone", "address"})

ROLES: frozenset[str] = frozenset(r for roles in PERMISSIONS.values() for r in roles)

# Import-time sanity checks: a typo in the tables stops the app from starting.
_valid_roles = {r.value for r in Role}
assert ROLES <= _valid_roles, f"unknown role in PERMISSIONS: {ROLES - _valid_roles}"
assert set(BENEFICIARY_PII) <= _valid_roles, "unknown role in BENEFICIARY_PII"
for _cap, _roles in OWN_ONLY.items():
    assert _cap in PERMISSIONS and _roles <= PERMISSIONS[_cap], f"OWN_ONLY mismatch: {_cap}"


def roles_with(capability: str) -> frozenset[str]:
    """Roles that hold a capability. An unknown capability is a programming error."""
    try:
        return PERMISSIONS[capability]
    except KeyError:
        raise KeyError(f"Unknown capability {capability!r}; add it to PERMISSIONS") from None


def has_capability(user: User, capability: str) -> bool:
    return user.role in roles_with(capability)


# ---------------------------------------------------------------------------
# 3. Authentication, and the dependencies that read the table.
# ---------------------------------------------------------------------------
# auto_error=False: if the header is missing we raise our own 401, so the body
# uses the standard {"error": {...}} format.
bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    # ONE message for every failure (no header, bad signature, expired, logged
    # out, user gone, user disabled). Different messages would tell an attacker
    # which check they got past.
    return HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail="You do not have permission to do this")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Return the logged-in user, or raise 401."""
    if credentials is None:
        raise _unauthorized()

    try:
        claims = decode_access_token(credentials.credentials)
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError):
        # Bad signature, expired, malformed, or a non-numeric sub.
        raise _unauthorized()

    # Logged-out token? Checked before anything else about the user.
    if db.get(TokenDenylist, claims["jti"]) is not None:
        raise _unauthorized()

    # Always load the user fresh from the database. The role and the
    # is_active flag in the DB are the truth, not whatever the token says, so
    # deactivating a user or changing their role takes effect on their very
    # next request instead of when their token expires.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def require_capability(capability: str):
    """Dependency factory: `Depends(require_capability("view_donations"))`.

    Authentication happens first (get_current_user -> 401). Only then is the
    table consulted (-> 403), so an anonymous caller learns nothing about roles.
    The capability name is looked up when the route is defined, so a typo fails
    at startup instead of silently locking everyone out.
    """
    allowed = roles_with(capability)

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise _forbidden()
        return user

    checker.capability = capability  # lets tests and tooling see what a route demands
    return checker


def require_roles(*allowed: str):
    """Low-level form: allow an explicit set of roles.

    Endpoints must not use this (a test enforces it); they ask for a capability.
    It still reads the table: every role named must be one PERMISSIONS knows.
    """
    unknown = set(allowed) - ROLES
    if unknown:
        raise ValueError(f"Role(s) not present in PERMISSIONS: {sorted(unknown)}")

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise _forbidden()
        return user

    return checker


# ---------------------------------------------------------------------------
# 4. Scope helpers: rules a role check cannot express. Small and named, so
#    endpoints call them instead of writing ifs. Rows are matched by attribute
#    (Beneficiary.assigned_officer_id, Distribution.officer_id), so these work
#    as soon as those models exist.
# ---------------------------------------------------------------------------
def is_own_only(user: User, capability: str) -> bool:
    """True if this user holds the capability but only for rows that are theirs."""
    return user.role in OWN_ONLY.get(capability, frozenset())


def can_access_row(user: User, capability: str, row: Any, owner_attr: str) -> bool:
    """May `user` use `row` under `capability`? Own-only roles must own the row."""
    if not has_capability(user, capability):
        return False
    if is_own_only(user, capability):
        return getattr(row, owner_attr, None) == user.id
    return True


def restrict_to_own(stmt, user: User, capability: str, owner_column):
    """Narrow a SELECT: own-only roles get their rows, roles without the
    capability get nothing (fail closed), everyone else is unchanged."""
    if not has_capability(user, capability):
        return stmt.where(false())
    if is_own_only(user, capability):
        return stmt.where(owner_column == user.id)
    return stmt


# A field officer sees only the beneficiaries assigned to them.
def scope_beneficiaries(stmt, user: User, model):
    return restrict_to_own(stmt, user, "view_beneficiary", model.assigned_officer_id)


def can_view_beneficiary(user: User, beneficiary: Any) -> bool:
    return can_access_row(user, "view_beneficiary", beneficiary, "assigned_officer_id")


# A field officer creates and signs only their own distributions.
def can_sign_distribution(user: User, distribution: Any) -> bool:
    return can_access_row(user, "sign_distribution", distribution, "officer_id")


def mask_value(value: Any) -> Any:
    """'1234567890' -> '******7890'. Values of 4 characters or fewer are fully hidden."""
    if not isinstance(value, str) or value == "":
        return value
    return "*" * (len(value) - 4) + value[-4:] if len(value) > 4 else "*" * len(value)


# Admin sees masked values; auditor sees no PII at all.
def redact_beneficiary(user: User, data: dict) -> dict:
    """Return a copy of a beneficiary dict with PII shown, masked or removed."""
    level = BENEFICIARY_PII.get(user.role, NONE)
    if level == FULL:
        return dict(data)
    if level == MASKED:
        return {k: mask_value(v) if k in BENEFICIARY_PII_FIELDS else v for k, v in data.items()}
    return {k: v for k, v in data.items() if k not in BENEFICIARY_PII_FIELDS}
