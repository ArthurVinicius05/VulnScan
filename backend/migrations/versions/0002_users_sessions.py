"""Adiciona contas, sessões e propriedade das auditorias."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_users_sessions"
down_revision: Union[str, None] = "0001_audit_records"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"], unique=False)
    op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True)
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"], unique=False)
    op.add_column("audit_records", sa.Column("user_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_audit_records_user_id_users", "audit_records", "users", ["user_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_audit_records_user_id", "audit_records", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_records_user_id", table_name="audit_records")
    op.drop_constraint("fk_audit_records_user_id_users", "audit_records", type_="foreignkey")
    op.drop_column("audit_records", "user_id")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_token_hash", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
