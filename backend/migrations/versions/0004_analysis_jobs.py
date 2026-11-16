"""Adiciona fila durável de análises e vínculo idempotente ao histórico."""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "0004_analysis_jobs"
down_revision: Union[str, None] = "0003_account_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table("analysis_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("archive_data", sa.LargeBinary(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"))
    for name, column in [("user_id","user_id"),("status","status"),("created_at","created_at"),("available_at","available_at"),("lease_expires_at","lease_expires_at")]:
        op.create_index(f"ix_analysis_jobs_{name}", "analysis_jobs", [column])
    with op.batch_alter_table("audit_records") as batch_op:
        batch_op.add_column(sa.Column("job_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key("fk_audit_records_job_id_analysis_jobs", "analysis_jobs", ["job_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_audit_records_job_id", ["job_id"], unique=True)

def downgrade() -> None:
    with op.batch_alter_table("audit_records") as batch_op:
        batch_op.drop_index("ix_audit_records_job_id")
        batch_op.drop_constraint("fk_audit_records_job_id_analysis_jobs", type_="foreignkey")
        batch_op.drop_column("job_id")
    for name in ["lease_expires_at","available_at","created_at","status","user_id"]:
        op.drop_index(f"ix_analysis_jobs_{name}", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
