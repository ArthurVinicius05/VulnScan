"""Cria a tabela inicial de auditorias."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_audit_records"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_records_analysis_type", "audit_records", ["analysis_type"], unique=False)
    op.create_index("ix_audit_records_created_at", "audit_records", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_records_created_at", table_name="audit_records")
    op.drop_index("ix_audit_records_analysis_type", table_name="audit_records")
    op.drop_table("audit_records")
