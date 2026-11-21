# n8n, Phase 19

Versionierte Definitionen liegen unter workflows/n8n. Die eigene Datenbank heißt n8n;
Fachentscheidungen liegen in automation innerhalb cve_monitoring. CLI:
CVE_DOCKER_SUDO=1 make notifications-build notifications-up. Keine öffentlichen Webhooks,
SMTP-Nodes oder SQL-Zugriffe auf die Fachanwendung.
[Architektur](../../docs/n8n/architecture.md), [Betrieb/Recovery](../../docs/n8n/recovery.md).
