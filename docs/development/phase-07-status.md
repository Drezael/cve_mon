# Phase-7-Arbeitsstand

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge abgeschlossen.**

[Abnahme](phase-07-acceptance.md), [Dateiliste](phase-07-files.json), [Übergabe](phase-07-handover.md).

| Auftrag | Inhalt | Status | Umsetzung | Nachweis |
|---|---|---|---|---|
| T07.01.01 | Bestehende Job- und Ereignisarchitektur analysieren | completed | docs/architecture/background-jobs.md; worker-lifecycle.md; transactional-outbox.md | unit/test_contracts.py; phase-07-plan.md |
| T07.01.02 | Jobtypen und Ausführungsverträge definieren | completed | docs/architecture/background-jobs.md; worker-lifecycle.md; transactional-outbox.md | unit/test_contracts.py; phase-07-plan.md |
| T07.01.03 | Job- und Outbox-Zustandsautomaten definieren | completed | docs/architecture/background-jobs.md; worker-lifecycle.md; transactional-outbox.md | unit/test_contracts.py; phase-07-plan.md |
| T07.01.04 | Zustellgarantien und Idempotenz spezifizieren | completed | docs/architecture/background-jobs.md; worker-lifecycle.md; transactional-outbox.md | unit/test_contracts.py; phase-07-plan.md |
| T07.01.05 | Schnittstellen und Verantwortlichkeiten | completed | docs/architecture/background-jobs.md; worker-lifecycle.md; transactional-outbox.md | unit/test_contracts.py; phase-07-plan.md |
| T07.02.01 | Automation-Schema prüfen | completed | database/migrations/versions/00013_automation_runtime.py; docs/database/automation-runtime.md | test_jobs.py; test_events.py; PostgreSQL-Regression 189 |
| T07.02.02 | Job- und Versuchstabellen vervollständigen | completed | database/migrations/versions/00013_automation_runtime.py; docs/database/automation-runtime.md | test_jobs.py; test_events.py; PostgreSQL-Regression 189 |
| T07.02.03 | Lease-, Fencing- und Queue-Indizes | completed | database/migrations/versions/00013_automation_runtime.py; docs/database/automation-runtime.md | test_jobs.py; test_events.py; PostgreSQL-Regression 189 |
| T07.02.04 | Outbox- und Idempotenzdaten ergänzen | completed | database/migrations/versions/00013_automation_runtime.py; docs/database/automation-runtime.md | test_jobs.py; test_events.py; PostgreSQL-Regression 189 |
| T07.02.05 | Datenbankrechte und Migrationen testen | completed | database/migrations/versions/00013_automation_runtime.py; docs/database/automation-runtime.md | test_jobs.py; test_events.py; PostgreSQL-Regression 189 |
| T07.03.01 | Persistente Job-Erstellung | completed | cve_common/jobs/repository.py; claim.py; leases.py; native SQL-Funktionen | test_jobs.py: Idempotenz, parallele Claims, Heartbeat, Fencing |
| T07.03.02 | Idempotente Job-Erstellung | completed | cve_common/jobs/repository.py; claim.py; leases.py; native SQL-Funktionen | test_jobs.py: Idempotenz, parallele Claims, Heartbeat, Fencing |
| T07.03.03 | Atomare Jobreservierung | completed | cve_common/jobs/repository.py; claim.py; leases.py; native SQL-Funktionen | test_jobs.py: Idempotenz, parallele Claims, Heartbeat, Fencing |
| T07.03.04 | Heartbeats und Lease-Verlängerung | completed | cve_common/jobs/repository.py; claim.py; leases.py; native SQL-Funktionen | test_jobs.py: Idempotenz, parallele Claims, Heartbeat, Fencing |
| T07.03.05 | Fencing und Reservierungstests | completed | cve_common/jobs/repository.py; claim.py; leases.py; native SQL-Funktionen | test_jobs.py: Idempotenz, parallele Claims, Heartbeat, Fencing |
| T07.04.01 | Worker Runtime und Handler Registry | completed | cve_common/jobs/registry.py; execution.py; worker.py | test_workers.py; test_resilience.py; test_performance.py |
| T07.04.02 | Isolierte Jobausführung | completed | cve_common/jobs/registry.py; execution.py; worker.py | test_workers.py; test_resilience.py; test_performance.py |
| T07.04.03 | Parallelität und Backpressure | completed | cve_common/jobs/registry.py; execution.py; worker.py | test_workers.py; test_resilience.py; test_performance.py |
| T07.04.04 | Kontrollierter Shutdown | completed | cve_common/jobs/registry.py; execution.py; worker.py | test_workers.py; test_resilience.py; test_performance.py |
| T07.04.05 | Worker-Parallelität und Prozessausfälle | completed | cve_common/jobs/registry.py; execution.py; worker.py | test_workers.py; test_resilience.py; test_performance.py |
| T07.05.01 | Fehlerklassifizierung | completed | cve_common/jobs/errors.py; retries.py; cancellation.py; SQL-Recovery/control_job | test_resilience.py; test_jobs.py; unit/test_contracts.py |
| T07.05.02 | Retry-Policy und Backoff | completed | cve_common/jobs/errors.py; retries.py; cancellation.py; SQL-Recovery/control_job | test_resilience.py; test_jobs.py; unit/test_contracts.py |
| T07.05.03 | Lease-Recovery und Job-Timeouts | completed | cve_common/jobs/errors.py; retries.py; cancellation.py; SQL-Recovery/control_job | test_resilience.py; test_jobs.py; unit/test_contracts.py |
| T07.05.04 | Dead-Letter-Verwaltung | completed | cve_common/jobs/errors.py; retries.py; cancellation.py; SQL-Recovery/control_job | test_resilience.py; test_jobs.py; unit/test_contracts.py |
| T07.05.05 | Abbruch und Wiederaufnahme | completed | cve_common/jobs/errors.py; retries.py; cancellation.py; SQL-Recovery/control_job | test_resilience.py; test_jobs.py; unit/test_contracts.py |
| T07.06.01 | Transactional-Outbox-Writer | completed | cve_common/events/outbox.py; delivery.py; transport.py; SQL-Zustellfunktionen | test_events.py; test_dispatcher.py: Rollback, HTTPS, Ack-Verlust, SIGKILL |
| T07.06.02 | Outbox-Reservierung | completed | cve_common/events/outbox.py; delivery.py; transport.py; SQL-Zustellfunktionen | test_events.py; test_dispatcher.py: Rollback, HTTPS, Ack-Verlust, SIGKILL |
| T07.06.03 | Event Dispatcher und Transport | completed | cve_common/events/outbox.py; delivery.py; transport.py; SQL-Zustellfunktionen | test_events.py; test_dispatcher.py: Rollback, HTTPS, Ack-Verlust, SIGKILL |
| T07.06.04 | Zustellbestätigung und Fehlerhistorie | completed | cve_common/events/outbox.py; delivery.py; transport.py; SQL-Zustellfunktionen | test_events.py; test_dispatcher.py: Rollback, HTTPS, Ack-Verlust, SIGKILL |
| T07.06.05 | Outbox-Absturz- und Recovery-Tests | completed | cve_common/events/outbox.py; delivery.py; transport.py; SQL-Zustellfunktionen | test_events.py; test_dispatcher.py: Rollback, HTTPS, Ack-Verlust, SIGKILL |
| T07.07.01 | Versionierte Ereignisverträge | completed | contracts/jobs/; contracts/events/; events/idempotency.py; registry.py | test_events.py; test_dispatcher.py; unit/test_contracts.py |
| T07.07.02 | Idempotente Event-Consumer | completed | contracts/jobs/; contracts/events/; events/idempotency.py; registry.py | test_events.py; test_dispatcher.py; unit/test_contracts.py |
| T07.07.03 | Ereignisreihenfolge | completed | contracts/jobs/; contracts/events/; events/idempotency.py; registry.py | test_events.py; test_dispatcher.py; unit/test_contracts.py |
| T07.07.04 | Sichere Zustellziele und Transporte | completed | contracts/jobs/; contracts/events/; events/idempotency.py; registry.py | test_events.py; test_dispatcher.py; unit/test_contracts.py |
| T07.07.05 | Event-Sicherheit und Idempotenztests | completed | contracts/jobs/; contracts/events/; events/idempotency.py; registry.py | test_events.py; test_dispatcher.py; unit/test_contracts.py |
| T07.08.01 | Event-Dispatcher-Dockerimage | completed | services/event-dispatcher/; compose.yml; scripts/automation/; Makefile | test_dispatcher.py; Installation und lokale Betriebsprüfung |
| T07.08.02 | Dispatcher in Docker Compose | completed | services/event-dispatcher/; compose.yml; scripts/automation/; Makefile | test_dispatcher.py; Installation und lokale Betriebsprüfung |
| T07.08.03 | Administrative Inspektionswerkzeuge | completed | services/event-dispatcher/; compose.yml; scripts/automation/; Makefile | test_dispatcher.py; Installation und lokale Betriebsprüfung |
| T07.08.04 | Healthchecks und Monitoring | completed | services/event-dispatcher/; compose.yml; scripts/automation/; Makefile | test_dispatcher.py; Installation und lokale Betriebsprüfung |
| T07.08.05 | Docker-, Neustart- und Ausfalltests | completed | services/event-dispatcher/; compose.yml; scripts/automation/; Makefile | test_dispatcher.py; Installation und lokale Betriebsprüfung |
| T07.09.01 | Gesamte Automatisierungstestsuite | completed | tests/automation/; docs/testing/phase-07-test-matrix.md; Phase-7-Abnahme/Übergabe | 687 bestandene Tests; make check; setup/python-check; Messbericht |
| T07.09.02 | Absturz-, Konkurrenz- und Recovery-Tests | completed | tests/automation/; docs/testing/phase-07-test-matrix.md; Phase-7-Abnahme/Übergabe | 687 bestandene Tests; make check; setup/python-check; Messbericht |
| T07.09.03 | Performance und Fairness | completed | tests/automation/; docs/testing/phase-07-test-matrix.md; Phase-7-Abnahme/Übergabe | 687 bestandene Tests; make check; setup/python-check; Messbericht |
| T07.09.04 | Dokumentation | completed | tests/automation/; docs/testing/phase-07-test-matrix.md; Phase-7-Abnahme/Übergabe | 687 bestandene Tests; make check; setup/python-check; Messbericht |
| T07.09.05 | Gesamtabnahme und Übergabe | completed | tests/automation/; docs/testing/phase-07-test-matrix.md; Phase-7-Abnahme/Übergabe | 687 bestandene Tests; make check; setup/python-check; Messbericht |
