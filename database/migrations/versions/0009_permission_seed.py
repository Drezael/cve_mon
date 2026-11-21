"""permission seed — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0009_permission_seed"
down_revision = "0008_privileges_seeds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
INSERT INTO security.permissions(code,description) VALUES
('cve:read','cve:read'),
('deployment:status:read','deployment:status:read'),
('events:deliver','events:deliver'),
('findings:read','findings:read'),
('findings:write','findings:write'),
('groups:manage','groups:manage'),
('health:read','health:read'),
('inventory:read','inventory:read'),
('inventory:submit','inventory:submit'),
('inventory:upload:dashboard','inventory:upload:dashboard'),
('jobs:cve.enrich','jobs:cve.enrich'),
('jobs:cve.import','jobs:cve.import'),
('jobs:findings.reconcile','jobs:findings.reconcile'),
('jobs:matching.run','jobs:matching.run'),
('jobs:notification.send','jobs:notification.send'),
('jobs:report.generate','jobs:report.generate'),
('matching:read','matching:read'),
('metrics:read','metrics:read'),
('preauth','preauth'),
('public','public'),
('reports:create','reports:create'),
('reports:read','reports:read'),
('roles:manage','roles:manage'),
('servers:manage','servers:manage'),
('session:self','session:self'),
('tokens:manage','tokens:manage'),
('users:manage','users:manage')
ON CONFLICT(code) DO NOTHING;
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p
WHERE r.code='admin'
OR (r.code='user_admin' AND (p.code LIKE 'users:%' OR p.code LIKE 'roles:%' OR p.code LIKE 'audit:%'))
OR (r.code='security_analyst' AND (p.code LIKE '%:read' OR p.code IN ('inventory:upload:dashboard','findings:write','reports:create')))
OR (r.code='viewer' AND p.code LIKE '%:read' AND p.code NOT LIKE 'audit:%' AND p.code NOT LIKE 'users:%' AND p.code NOT LIKE 'roles:%')
ON CONFLICT DO NOTHING;
"""
