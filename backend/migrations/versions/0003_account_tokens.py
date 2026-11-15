"""Adiciona tokens de verificação de e-mail e recuperação de senha."""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003_account_tokens"
down_revision: Union[str, None] = "0002_users_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    # Preserve access for accounts created before email verification existed.
    op.execute("UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL")
    op.create_table("account_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("token_hash"))
    op.create_index("ix_account_tokens_user_id", "account_tokens", ["user_id"])
    op.create_index("ix_account_tokens_token_hash", "account_tokens", ["token_hash"], unique=True)
    op.create_index("ix_account_tokens_purpose", "account_tokens", ["purpose"])
    op.create_index("ix_account_tokens_expires_at", "account_tokens", ["expires_at"])

def downgrade() -> None:
    op.drop_index("ix_account_tokens_expires_at", table_name="account_tokens")
    op.drop_index("ix_account_tokens_purpose", table_name="account_tokens")
    op.drop_index("ix_account_tokens_token_hash", table_name="account_tokens")
    op.drop_index("ix_account_tokens_user_id", table_name="account_tokens")
    op.drop_table("account_tokens")
    op.drop_column("users", "email_verified_at")
