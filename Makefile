.DEFAULT_GOAL := help
VENV := .venv/bin
PYTHON := $(VENV)/python

.PHONY: help setup lint format format-check typecheck test validate security check
help:
	@printf '%s\n' 'setup         Entwicklungsumgebung einrichten' 'lint          Ruff-Linting' 'format        Python formatieren' 'format-check  Formatierung prüfen' 'typecheck     Mypy ausführen' 'test          Pytest ausführen' 'validate      Struktur, YAML, JSON und Schemas prüfen' 'security      Secrets prüfen (auch neue Dateien)' 'check         Alle verpflichtenden Qualitätsprüfungen' 'help          Diese Hilfe anzeigen' 'dev-certs     Lokale Test-PKI erstellen (keine Überschreibung)' 'compose-check Compose ohne Daemon validieren' 'nginx-check   Gerenderte Konfiguration mit gepinntem Nginx prüfen' 'infra-test    Isolierte Docker-/TLS-/Netzwerktests' 'infra-security TLS-/Ingress-/Netzwerksicherheit prüfen' 'infra-up      Lokalen Nginx starten' 'infra-down    Nur das gewählte Projekt stoppen' 'infra-reload  Validieren und Nginx sicher neu laden' 'db-secrets    Lokale getrennte DB-Credentials/TLS' 'db-up         PostgreSQL ohne Hostport starten' 'db-provision  Rollen ohne Passwortreset provisionieren' 'db-migrate    Alembic auf Head ausführen' 'db-check      Schema und echte Logins prüfen' 'db-test       Isolierte Integrität/Persistenz/Restore' 'db-backup     Beide Datenbanken sichern' 'db-restore-test Backup isoliert wiederherstellen' 'db-down       PostgreSQL stoppen, Daten erhalten'
	@printf '%s\n' 'mail-build    Unverändertes Postfix-Image laden' 'mail-secrets  Geschlossene lokale Test-PKI vorbereiten' 'mail-up       Postfix mit direktem SMTP starten' 'mail-down     Postfix stoppen, Queue erhalten' 'postfix-check Native Konfiguration und lokale Gesundheit' 'postfix-test  Vollständige isolierte SMTP-/Queue-Tests' 'postfix-security Negative SMTP-Sicherheitsprüfungen' 'postfix-queue-test Retry Persistenz Rotation Recovery' 'postfix-relay-test Interne/externe TLS-AUTH-Kette' 'mail-backup   Gestoppte Queue konsistent sichern' 'mail-restore  Auf eigene gestoppte leere Queue wiederherstellen'
setup:
	./cve_mon setup
lint:
	$(VENV)/ruff check . cve_mon
format:
	$(VENV)/ruff format . cve_mon
format-check:
	$(VENV)/ruff format --check . cve_mon
typecheck:
	$(VENV)/mypy
test:
	CVE_ENV_FILE="$${CVE_ENV_FILE:-configuration/examples/development.env}" $(PYTHON) -m pytest
validate:
	$(PYTHON) scripts/validate_repository.py
security:
	$(PYTHON) scripts/scan_secrets.py
check: lint format-check typecheck test validate security

.PHONY: dev-certs compose-check nginx-check infra-test infra-security infra-up infra-down infra-reload

dev-certs:
	./scripts/development/generate-dev-certificates.sh
compose-check:
	$(PYTHON) -m scripts.infrastructure.manage compose-check
nginx-check:
	./scripts/infrastructure/check-nginx-config.sh
infra-up:
	$(PYTHON) -m scripts.infrastructure.manage up
infra-down:
	$(PYTHON) -m scripts.infrastructure.manage down
infra-reload:
	$(PYTHON) -m scripts.infrastructure.manage reload
infra-test:
	$(PYTHON) -m pytest -m infrastructure tests/infrastructure
infra-security:
	$(PYTHON) -m pytest -m 'infrastructure and security' tests/infrastructure

.PHONY: db-secrets db-up db-down db-provision db-migrate db-check db-test db-security-test db-backup db-restore-test
DB := $(PYTHON) -m scripts.database.manage
db-secrets:
	$(DB) secrets
db-up:
	$(DB) up
db-down:
	$(DB) down
db-provision:
	$(DB) provision
db-migrate:
	$(DB) migrate
db-check:
	$(DB) verify
db-test:
	$(PYTHON) -m pytest -m database tests/database
db-security-test:
	$(PYTHON) -m pytest -m database tests/database/test_roles.py
db-backup:
	$(DB) backup $(if $(BACKUP_DIR),--backup-dir "$(BACKUP_DIR)")
db-restore-test:
	$(DB) restore-test --backup-dir "$(BACKUP_DIR)"

.PHONY: db-security db-backup-test
db-security: db-security-test
db-backup-test:
	$(PYTHON) -m pytest -m database tests/database/test_operations.py -k full_backup_restore


.PHONY: mail-build mail-secrets mail-up mail-down mail-check mail-test mail-security mail-queue mail-flush mail-backup mail-restore
MAIL := $(PYTHON) -m scripts.infrastructure.mail
mail-build:
	$(MAIL) build
mail-secrets:
	$(MAIL) secrets
mail-up:
	$(MAIL) up
mail-down:
	$(MAIL) down
mail-check:
	$(MAIL) check
mail-test:
	$(PYTHON) -m pytest -m mail tests/infrastructure/mail
mail-security:
	$(PYTHON) -m pytest -m 'mail and security' tests/infrastructure/mail
mail-queue:
	$(MAIL) queue
mail-flush:
	$(MAIL) flush
mail-backup:
	$(MAIL) backup --backup-dir "$(BACKUP_DIR)"
mail-restore:
	$(MAIL) restore --backup-dir "$(BACKUP_DIR)"

.PHONY: postfix-check postfix-test postfix-security postfix-queue-test postfix-relay-test
postfix-check: mail-check
postfix-test: mail-test
postfix-security: mail-security
postfix-queue-test:
	$(PYTHON) -m pytest -m mail tests/infrastructure/mail/test_reliability.py tests/infrastructure/mail/test_operations.py
postfix-relay-test:
	$(PYTHON) -m pytest -m mail tests/infrastructure/mail/test_submission.py tests/infrastructure/mail/test_reliability.py -k 'submission or end_to_end or failed_upstream'

.PHONY: python-check services-test services-security services-integration api-build api-prepare api-up api-down api-smoke-test
API := $(PYTHON) -m scripts.services.manage
python-check: lint format-check typecheck
	./scripts/services/check-python-runtime.sh
services-test:
	$(PYTHON) -m pytest -m 'not services_integration' tests/services
services-security:
	$(PYTHON) -m pytest -m 'security and not services_integration' tests/services
services-integration:
	$(PYTHON) -m pytest -m services_integration tests/services/integration
api-build:
	$(API) build
api-prepare:
	$(API) prepare
api-up:
	$(API) up
api-down:
	$(API) down
api-smoke-test:
	$(API) smoke

.PHONY: jobs-check jobs-test jobs-security jobs-concurrency-test outbox-test outbox-security dispatcher-test automation-integration dispatcher-build dispatcher-prepare dispatcher-up dispatcher-down
AUTOMATION := $(PYTHON) -m scripts.automation.manage
jobs-check: python-check
	$(AUTOMATION) check
jobs-test:
	$(PYTHON) -m pytest tests/automation/unit
	$(PYTHON) -m pytest -m automation tests/automation/integration/test_jobs.py tests/automation/integration/test_workers.py tests/automation/integration/test_resilience.py
jobs-security:
	$(PYTHON) -m pytest -m 'automation and security' tests/automation/integration/test_jobs.py tests/automation/integration/test_workers.py tests/automation/integration/test_resilience.py
jobs-concurrency-test:
	$(PYTHON) -m pytest -m automation tests/automation/integration/test_jobs.py tests/automation/integration/test_performance.py
outbox-test:
	$(PYTHON) -m pytest -m automation tests/automation/integration/test_events.py
outbox-security: outbox-test
dispatcher-test:
	$(PYTHON) -m pytest -m automation tests/automation/integration/test_dispatcher.py
automation-integration:
	$(PYTHON) -m pytest -m automation tests/automation/integration
dispatcher-build:
	$(AUTOMATION) build
dispatcher-prepare:
	$(AUTOMATION) prepare
dispatcher-up:
	$(AUTOMATION) up
dispatcher-down:
	$(AUTOMATION) down

.PHONY: auth-check auth-test auth-security auth-integration auth-mfa-test
AUTH := $(PYTHON) -m scripts.security.manage
auth-check: python-check
	$(AUTH) check
auth-test:
	$(PYTHON) -m pytest tests/authentication/unit
auth-security:
	$(PYTHON) -m pytest -m 'authentication and security' tests/authentication/integration
auth-integration:
	$(PYTHON) -m pytest -m authentication tests/authentication/integration
auth-mfa-test:
	$(PYTHON) -m pytest -m authentication tests/authentication/integration -k 'mfa or totp or recovery or reauth'

.PHONY: authorization-check authorization-test authorization-security authorization-integration authorization-concurrency
authorization-check: python-check
	$(PYTHON) -m scripts.security.authorization check
authorization-test:
	$(PYTHON) -m pytest tests/authorization/unit
authorization-security:
	$(PYTHON) -m pytest -m 'authorization and security' tests/authorization/integration
authorization-integration:
	$(PYTHON) -m pytest -m authorization tests/authorization/integration
authorization-concurrency:
	$(PYTHON) -m pytest -m authorization tests/authorization/integration/test_concurrency.py

.PHONY: server-admin-check server-admin-test server-admin-security server-admin-integration server-admin-concurrency server-admin-integrity
server-admin-check: python-check
	$(PYTHON) -m scripts.administration.manage all
server-admin-test:
	$(PYTHON) -m pytest tests/server_administration/unit
server-admin-integration:
	./scripts/administration/run-server-admin-tests.sh
server-admin-security:
	$(PYTHON) -m pytest -m 'server_administration and security' tests/server_administration/integration
server-admin-concurrency:
	$(PYTHON) -m pytest -m server_administration tests/server_administration/integration/test_ordering.py
server-admin-integrity:
	$(PYTHON) -m scripts.administration.manage all

.PHONY: inventory-upload-check inventory-upload-test inventory-upload-security inventory-upload-integration inventory-upload-mtls inventory-upload-concurrency inventory-upload-e2e
inventory-upload-check: python-check
	$(PYTHON) -m scripts.inventory.manage contract
	$(PYTHON) -m scripts.inventory.manage mtls
	$(PYTHON) -m scripts.inventory.manage permissions
inventory-upload-test:
	$(PYTHON) -m pytest tests/inventory_upload/unit
inventory-upload-integration:
	./scripts/inventory/run-upload-tests.sh
inventory-upload-security:
	$(PYTHON) -m pytest -m 'inventory_upload and security' tests/inventory_upload/integration
inventory-upload-mtls:
	$(PYTHON) -m pytest -m inventory_upload tests/inventory_upload/integration/test_technical_security.py
inventory-upload-concurrency:
	$(PYTHON) -m pytest -m inventory_upload tests/inventory_upload/integration/test_concurrency_recovery.py
inventory-upload-e2e:
	$(PYTHON) -m pytest -m inventory_upload tests/inventory_upload/integration/test_concurrency_recovery.py -k 'real_deployment or real_dashboard'

.PHONY: inventory-collect-test inventory-collect-integration inventory-collect-syntax
inventory-collect-test:
	$(PYTHON) -m pytest tests/unit/test_ansible_readonly.py tests/unit/test_ansible_repository.py tests/inventory_upload/unit/test_collect_contract.py
inventory-collect-integration:
	PATH="$(CURDIR)/.venv/bin:$$PATH" $(PYTHON) -m pytest -m automation tests/managed_ansible/test_ssh_execution.py
inventory-collect-syntax:
	$(PYTHON) -m scripts.ansible.manage syntax

.PHONY: inventory-submit-test inventory-submit-integration inventory-submit-syntax
inventory-submit-test:
	$(PYTHON) -m pytest tests/unit/test_ansible_repository.py tests/unit/test_container_runner.py
inventory-submit-integration:
	$(PYTHON) -m pytest -m inventory_upload tests/inventory_upload/integration/test_ansible_submit.py
inventory-submit-syntax:
	$(PYTHON) -m compileall -q scripts/ansible

.PHONY: inventory-processor-check inventory-processor-build inventory-processor-up inventory-processor-down inventory-processor-test inventory-processor-integration inventory-processor-security inventory-processor-concurrency inventory-processor-performance inventory-processor-e2e
inventory-processor-check:
	$(VENV)/ruff check services/inventory scripts/inventory_processor tests/inventory_processor
	$(VENV)/mypy services/inventory/src scripts/inventory_processor tests/inventory_processor
	$(PYTHON) -m pytest tests/inventory_processor/test_normalization.py
inventory-processor-build:
	$(PYTHON) -m scripts.inventory_processor.manage build
inventory-processor-up:
	$(PYTHON) -m scripts.inventory_processor.manage up
inventory-processor-down:
	$(PYTHON) -m scripts.inventory_processor.manage down
inventory-processor-test inventory-processor-integration:
	$(PYTHON) -m pytest -m inventory_processor tests/inventory_processor
inventory-processor-security:
	$(PYTHON) -m pytest -m inventory_processor tests/inventory_processor -k 'sealed or permissions or archive or rejection'
inventory-processor-concurrency:
	$(PYTHON) -m pytest -m inventory_processor tests/inventory_processor -k 'current_history or stale_fence or backfill'
inventory-processor-performance:
	$(PYTHON) -m pytest -m inventory_processor tests/inventory_processor -k large_package --junitxml=.runtime/test-reports/phase-14-performance.xml
inventory-processor-e2e:
	$(PYTHON) -m pytest -m inventory_processor tests/inventory_processor -k e2e

.PHONY: cve-importer-check cve-importer-build cve-importer-up cve-importer-down cve-importer-test cve-importer-integration cve-importer-security cve-importer-concurrency cve-importer-performance cve-importer-e2e
cve-importer-check:
	$(VENV)/ruff check services/importer/src scripts/cve_importer tests/cve_importer
	$(VENV)/mypy services/importer/src scripts/cve_importer tests/cve_importer
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer/test_validation.py tests/cve_importer/test_transport.py
cve-importer-build:
	$(PYTHON) -m scripts.cve_importer.manage build
cve-importer-up:
	$(PYTHON) -m scripts.cve_importer.manage up
cve-importer-down:
	$(PYTHON) -m scripts.cve_importer.manage down
cve-importer-test cve-importer-integration:
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer
cve-importer-security:
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer -k 'security or permission or forbidden or proof or archive or denial'
cve-importer-concurrency:
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer -k 'serialization or concurrency or recovery or fence'
cve-importer-performance:
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer -k performance --junitxml=.runtime/test-reports/phase-15-performance.xml
cve-importer-e2e:
	$(PYTHON) -m pytest -m cve_importer tests/cve_importer -k e2e

.PHONY: cve-enricher-check cve-enricher-build cve-enricher-up cve-enricher-down cve-enricher-test cve-enricher-integration cve-enricher-security cve-enricher-concurrency cve-enricher-performance cve-enricher-e2e cvss-test epss-test
cve-enricher-check:
	$(VENV)/ruff check services/enricher/src scripts/cve_enricher tests/cve_enricher
	$(VENV)/mypy services/enricher/src scripts/cve_enricher tests/cve_enricher
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher/test_normalize.py tests/cve_enricher/test_epss.py
cve-enricher-build:
	$(PYTHON) -m scripts.cve_enricher.manage build
cve-enricher-up:
	$(PYTHON) -m scripts.cve_enricher.manage up
cve-enricher-down:
	$(PYTHON) -m scripts.cve_enricher.manage down
cve-enricher-test cve-enricher-integration:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher
cve-enricher-security:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher -k 'forbidden or invalid or permission or immutability or security or sealed'
cve-enricher-concurrency:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher -k 'concurrency or recovery or fence or alias'
cve-enricher-performance:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher -k performance --junitxml=.runtime/test-reports/phase-16-performance.xml
cve-enricher-e2e:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher -k e2e
cvss-test:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher/test_normalize.py -k cvss
epss-test:
	$(PYTHON) -m pytest -m cve_enricher tests/cve_enricher -k epss

.PHONY: matching-check matching-build matching-up matching-down matching-test matching-integration matching-versions-test matching-security matching-concurrency matching-performance matching-e2e
matching-check:
	$(VENV)/ruff check services/matcher scripts/cve_matcher tests/matching
	$(VENV)/mypy services/matcher/src scripts/cve_matcher tests/matching
	$(PYTHON) -m pytest -m matching tests/matching/test_versions.py tests/matching/test_engine.py
matching-build:
	$(PYTHON) -m scripts.cve_matcher.manage build
matching-up:
	$(PYTHON) -m scripts.cve_matcher.manage up
matching-down:
	$(PYTHON) -m scripts.cve_matcher.manage down
matching-test matching-integration:
	$(PYTHON) -m pytest -m matching tests/matching
matching-versions-test:
	$(PYTHON) -m pytest -m matching tests/matching/test_versions.py
matching-security:
	$(PYTHON) -m pytest -m matching tests/matching -k 'permissions or immutability or network or guard or injection'
matching-concurrency:
	$(PYTHON) -m pytest -m matching tests/matching -k 'concurrency or stale or recovery or lease'
matching-performance:
	$(PYTHON) -m pytest -m matching tests/matching -k performance --junitxml=.runtime/test-reports/phase-17-performance.xml
matching-e2e:
	$(PYTHON) -m pytest -m matching tests/matching -k e2e

.PHONY: findings-check findings-build findings-up findings-down findings-test findings-integration findings-security findings-concurrency findings-performance findings-e2e
findings-check:
	$(VENV)/ruff check services/findings services/api/src/cve_api/findings scripts/cve_findings tests/findings
	$(VENV)/mypy services/findings/src services/api/src/cve_api/findings scripts/cve_findings tests/findings
	$(PYTHON) -m pytest -m findings tests/findings/test_rules.py
findings-build:
	$(PYTHON) -m scripts.cve_findings.manage build
findings-up:
	$(PYTHON) -m scripts.cve_findings.manage up
findings-down:
	$(PYTHON) -m scripts.cve_findings.manage down
findings-test findings-integration:
	$(PYTHON) -m pytest -m findings tests/findings
findings-security:
	$(PYTHON) -m pytest -m findings tests/findings -k 'forbidden or scope or actor or guard or network or append_only or viewer'
findings-concurrency:
	$(PYTHON) -m pytest -m findings tests/findings -k 'concurrent or historical or lease or recovery'
findings-performance:
	$(PYTHON) -m pytest -m findings tests/findings -k performance --junitxml=.runtime/test-reports/phase-18-performance.xml
findings-e2e:
	$(PYTHON) -m pytest -m findings tests/findings -k 'e2e or recurrence'


.PHONY: notifications-check notifications-build notifications-up notifications-down notifications-test notifications-integration notifications-workflows notifications-smtp-test notifications-security notifications-concurrency notifications-resilience notifications-performance notifications-e2e n8n-rotate
notifications-check:
	$(VENV)/ruff check services/notification services/api/src/cve_api/notifications scripts/notifications tests/notifications
	$(VENV)/mypy services/notification/src services/api/src/cve_api/notifications scripts/notifications tests/notifications
	$(PYTHON) -m pytest -m notifications tests/notifications/test_rules.py
notifications-build:
	$(PYTHON) -m scripts.notifications.manage build
notifications-up:
	$(PYTHON) -m scripts.notifications.manage up
notifications-down:
	$(PYTHON) -m scripts.notifications.manage down
n8n-rotate:
	$(PYTHON) -m scripts.notifications.manage rotate
notifications-test notifications-integration:
	$(PYTHON) -m pytest -m notifications tests/notifications
notifications-workflows:
	$(PYTHON) -m pytest -m notifications tests/notifications/test_container.py
notifications-smtp-test:
	$(PYTHON) -m pytest -m notifications tests/notifications -k 'smtp or relay or delivery'
notifications-security:
	$(PYTHON) -m pytest -m notifications tests/notifications -k 'cannot or unauthorized or scope or csrf or history or injection or reject'
notifications-concurrency:
	$(PYTHON) -m pytest -m notifications tests/notifications -k 'concurrent or claim or duplicate or fence'
notifications-resilience:
	$(PYTHON) -m pytest -m notifications tests/notifications -k 'failure or outage or restart or recovery or uncertain'
notifications-performance:
	$(PYTHON) -m pytest -m notifications tests/notifications -k performance
notifications-e2e:
	$(PYTHON) -m pytest -m notifications tests/notifications -k 'e2e or real_finding or real_n8n'

.PHONY: dashboard-build dashboard-check dashboard-test dashboard-e2e dashboard-up dashboard-contracts dashboard-security dashboard-accessibility dashboard-performance
dashboard-build:
	$(PYTHON) -m scripts.dashboard.manage build
dashboard-check:
	$(PYTHON) -m scripts.dashboard.manage check
dashboard-test:
	$(PYTHON) -m scripts.dashboard.manage test
dashboard-e2e dashboard-security dashboard-accessibility dashboard-performance:
	$(PYTHON) -m pytest -m dashboard tests/dashboard --junitxml=.runtime/test-reports/phase-20-native.xml
dashboard-up:
	$(PYTHON) -m scripts.dashboard.manage activate
dashboard-contracts:
	$(PYTHON) -m scripts.dashboard.contracts
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" services/dashboard/node_modules/.bin/openapi-typescript contracts/api/dashboard-read.openapi.json -o services/dashboard/src/generated/api.ts

.PHONY: administration-check administration-test administration-e2e administration-security administration-contracts
administration-check:
	$(PYTHON) -m scripts.dashboard.manage check
	$(VENV)/ruff check services/api/src/cve_api/dashboard tests/dashboard_administration
	$(VENV)/mypy services/api/src/cve_api/dashboard tests/dashboard_administration
administration-test administration-e2e administration-security:
	$(PYTHON) -m pytest -m dashboard_administration tests/dashboard_administration --junitxml=.runtime/test-reports/phase-21-native.xml
administration-contracts:
	$(PYTHON) -m scripts.dashboard.administration_contracts
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" services/dashboard/node_modules/.bin/openapi-typescript contracts/api/dashboard-administration.openapi.json -o services/dashboard/src/generated/administration.ts

.PHONY: status-check status-test status-integration status-api status-frontend status-security status-resilience status-concurrency status-performance status-e2e status-contracts
status-check:
	$(VENV)/ruff check services/api/src/cve_api/status scripts/status tests/status infrastructure/status
	$(VENV)/mypy services/api/src/cve_api/status scripts/status tests/status infrastructure/status
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" npm --prefix services/dashboard run typecheck
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" npm --prefix services/dashboard run lint
status-test:
	$(PYTHON) -m pytest tests/status/test_models.py tests/status/test_probes.py
status-integration status-api status-security status-resilience status-concurrency status-performance:
	$(PYTHON) -m pytest tests/status/test_native.py -m status_integration --junitxml=.runtime/test-reports/phase-22-native.xml
status-e2e:
	$(PYTHON) -m pytest tests/status/test_runtime.py -m status_integration --junitxml=.runtime/test-reports/phase-22-runtime.xml
status-frontend:
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" npm --prefix services/dashboard test
status-contracts:
	$(PYTHON) -m scripts.status.contracts
	PATH="$(CURDIR)/.runtime/node/node-v24.22.2-linux-x64/bin:$$PATH" services/dashboard/node_modules/.bin/openapi-typescript contracts/api/status.openapi.json -o services/dashboard/src/generated/status.ts

.PHONY: security-tools security-check security-static security-dependencies security-secrets security-images security-containers security-networks security-api security-auth security-rbac security-database security-uploads security-pipelines security-supply-chain security-e2e performance-baseline performance-api performance-database performance-upload performance-matching performance-workers performance-frontend performance-regression resilience-test recovery-test phase-23-acceptance
security-tools:
	$(PYTHON) -m scripts.hardening.manage tools
security-static: lint format-check typecheck validate
security-secrets: security
security-check: check
	$(PYTHON) -m pytest tests/hardening/test_controls.py tests/hardening/test_http.py
security-dependencies:
	$(PYTHON) -m scripts.hardening.manage dependencies
security-images:
	$(PYTHON) -m scripts.hardening.manage images
.PHONY: security-image-regressions
security-image-regressions:
	$(PYTHON) -m scripts.hardening.manage api-image
	$(PYTHON) -m scripts.hardening.manage inventory-image
	$(PYTHON) -m scripts.hardening.manage importer-image
	$(PYTHON) -m scripts.hardening.manage enricher-image
	$(PYTHON) -m scripts.hardening.manage matching-image
	$(PYTHON) -m scripts.hardening.manage findings-image
	$(PYTHON) -m scripts.hardening.manage notification-image
security-containers:
	$(PYTHON) -m scripts.hardening.manage containers
security-networks:
	$(PYTHON) -m scripts.hardening.manage networks
security-api:
	$(PYTHON) -m scripts.hardening.manage api
security-auth:
	$(PYTHON) -m scripts.hardening.manage auth
security-rbac:
	$(PYTHON) -m scripts.hardening.manage rbac
security-database:
	$(PYTHON) -m scripts.hardening.manage database
security-uploads:
	$(PYTHON) -m scripts.hardening.manage uploads
security-pipelines:
	$(PYTHON) -m scripts.hardening.manage pipelines
security-supply-chain: security-dependencies security-images
	$(PYTHON) -m scripts.hardening.manage provenance
security-e2e:
	$(PYTHON) -m scripts.hardening.manage hardening
performance-baseline:
	$(PYTHON) -m scripts.hardening.manage baseline
performance-api performance-database performance-upload performance-matching performance-regression:
	$(PYTHON) -m scripts.hardening.manage performance
performance-workers:
	$(PYTHON) -m pytest tests/automation/integration/test_performance.py -m automation --junitxml=.runtime/test-reports/phase-23-workers.xml
performance-frontend:
	$(PYTHON) -m scripts.hardening.manage frontend
resilience-test:
	$(PYTHON) -m scripts.hardening.manage resilience
recovery-test:
	$(PYTHON) -m pytest tests/hardening/test_recovery.py -m hardening --junitxml=.runtime/test-reports/phase-23-recovery.xml
phase-23-acceptance:
	$(PYTHON) -m scripts.hardening.deployment
	$(PYTHON) -m scripts.hardening.components
	$(PYTHON) -m scripts.hardening.manage provenance
	$(PYTHON) -m scripts.hardening.manage acceptance

.PHONY: deployment-check deployment-test deployment-build deployment-release deployment-preflight deployment-acceptance
deployment-check:
	$(VENV)/ruff check scripts/deployment tests/deployment scripts/database/catalog.py
	$(VENV)/mypy scripts/deployment tests/deployment
	$(PYTHON) -m pytest tests/deployment/test_controls.py tests/deployment/test_catalog.py tests/deployment/test_migrations.py tests/deployment/test_artifacts.py tests/deployment/test_acceptance.py tests/deployment/test_recovery_controls.py --junitxml=.runtime/test-reports/phase-24-unit.xml
deployment-test:
	$(PYTHON) -m pytest -m deployment tests/deployment --junitxml=.runtime/test-reports/phase-24-native.xml
deployment-build:
	$(PYTHON) -m scripts.deployment.manage build
deployment-release:
	$(PYTHON) -m scripts.deployment.manage release --version "$${RELEASE_VERSION:?RELEASE_VERSION required}" --bundle "$${RELEASE_BUNDLE:?RELEASE_BUNDLE required}"
deployment-preflight:
	$(PYTHON) -m scripts.deployment.manage preflight --environment "$${DEPLOY_ENVIRONMENT:?DEPLOY_ENVIRONMENT required}" --bundle "$${RELEASE_BUNDLE:?RELEASE_BUNDLE required}"
deployment-acceptance:
	$(PYTHON) -m scripts.deployment.acceptance

.PHONY: application-build application-up application-down application-check
application-build:
	./cve_mon build
application-up:
	./cve_mon start
application-down:
	./cve_mon stop
application-check:
	./cve_mon health

.PHONY: github-check
github-check:
	$(PYTHON) -m scripts.github_ready
