"""Nur CVE-Anwendungsdatenbank; transaktionale Migration mit PostgreSQL-Advisory-Lock."""

import sys
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.database.manage import migration_connection
from scripts.infrastructure.manage import load_config


def run_migrations(connection: Connection) -> None:
    if connection.exec_driver_sql("SELECT current_database()").scalar_one() != "cve_monitoring":
        raise ValueError("Alembic darf ausschließlich cve_monitoring verwalten")
    connection.exec_driver_sql("SET ROLE postgres_owner")
    connection.commit()
    context.configure(
        connection=connection,
        target_metadata=None,
        version_table_schema="public",
        transactional_ddl=True,
    )
    with context.begin_transaction():
        connection.execute(text("SELECT pg_advisory_xact_lock(2026030301)"))
        context.run_migrations()


if context.is_offline_mode():
    raise ValueError("Nur kontrollierte Online-Migrationen; keine ungeprüften Offline-DDL-Dumps")
provided = context.config.attributes.get("connection")
if provided is not None:
    run_migrations(provided)
else:
    engine = create_engine(
        "postgresql+psycopg://", creator=lambda: migration_connection(load_config())
    )
    try:
        with engine.connect() as connection:
            run_migrations(connection)
    finally:
        engine.dispose()
