"""Audit log entry point. STUB: becomes a real database-backed log in Week 2.

Callers use it like this and will not need to change:

    audit.record(db, "login_failure", actor_id=None, target="alice", outcome="failure")

RULES for whoever makes it real:
  * never put passwords, tokens or password hashes in `details`;
  * a "failure" record must be committed even though the request then returns
    an error, otherwise failed logins would vanish from the log.
"""
import logging

logger = logging.getLogger("aidflow.audit")


def record(
    db,
    action: str,
    *,
    actor_id: int | None = None,
    target: str | None = None,
    outcome: str = "success",
    details: dict | None = None,
) -> None:
    logger.info(
        "audit action=%s actor_id=%s target=%s outcome=%s details=%s",
        action, actor_id, target, outcome, details or {},
    )
