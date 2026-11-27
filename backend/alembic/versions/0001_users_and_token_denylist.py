"""users and token_denylist (ticket A-01)

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("password_hash", sa.String(100), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('admin', 'warehouse', 'field', 'auditor')", name="ck_users_role"
        ),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table(
        "token_denylist",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_token_denylist_expires_at", "token_denylist", ["expires_at"])


def downgrade() -> None:
    op.drop_table("token_denylist")
    op.drop_table("users")
