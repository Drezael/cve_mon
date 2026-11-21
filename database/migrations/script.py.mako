"""${message}"""
from alembic import op
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None


def upgrade() -> None:
    raise NotImplementedError("Explizite PostgreSQL-DDL und Tests erforderlich")


def downgrade() -> None:
    raise RuntimeError("Datenverlust vermeiden: geprüften Backup-/Restore-Pfad verwenden")
