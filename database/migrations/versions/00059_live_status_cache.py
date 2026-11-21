"""Keep recovery lookups indexed as successful job history grows."""

from alembic import op

revision = "00059_live_status_cache"
down_revision = "00058_service_watchdog"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve monitoring recovery and historical data")


DDL = r"""
-- The recovery function also supports legacy job rows, so its lookup must not
-- depend on the runtime_version=1 predicate of jobs_success_type_time.
CREATE INDEX jobs_recovered_type_time ON automation.jobs(job_type,finished_at DESC) WHERE status='succeeded';
ALTER FUNCTION automation.job_failure_unresolved(uuid) SET jit='off';
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00058_service_watchdog','00059_live_status_cache');
END $$;
"""
