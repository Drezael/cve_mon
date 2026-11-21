"""Allow the additive shared collection contract 1.1 without rewriting original submissions."""

from alembic import op

revision = "00018_inventory_collect_contract"
down_revision = "00017_inventory_acceptance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE inventory.submissions DROP CONSTRAINT submissions_schema_version_check")
    op.execute(
        "ALTER TABLE inventory.submissions ADD CONSTRAINT submissions_schema_version_check "
        "CHECK(schema_version IN ('1.0','1.1'))"
    )


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")
