# Finding Worker

Voraussetzung: DB-Head 00025, getrennte findings_writer-Credentials und API 0.18.0.
In Entwicklung CVE_DOCKER_SUDO=1 make findings-build und make findings-up verwenden.
Die private Konfiguration liegt unter .runtime/cve-findings/<projekt>. Produktion benötigt
extern bereitgestellte Credentials; vorhandene Dateien werden nicht zurückgesetzt.

Jobs: findings.consume_matching_event, reconcile, refresh_priority, check_deadlines,
check_exceptions, backfill, reevaluate und maintenance. Je Job maximal 100 Dispatcher-Inputs
pro Batch, weitere Seiten werden als referenzbasierte Folgejobs persistiert. Kein automatischer
Matching-Backfill beim Start. Ein Operator kann explizit scripts.cve_findings.manage enqueue
--kind reconcile starten. Die Wartung erfasst nur bestehende Findings, niemals neue CVEs.

Interne /health/live, /health/ready und /metrics. Metriken zeigen Lifecycle, Priorität,
Episoden, Wiedereröffnungen, Stale, Overdue, Ausnahmen, Jobs, Retries, Laufzeiten und echte
Outbox-Zustellrückstände. Es existiert keine weitere öffentliche Finding-Service-API.
Keine Nachrichtenkanäle oder n8n-Workflows werden in Phase 18 aktiviert.
