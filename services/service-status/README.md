# Systemstatus – Phase 22

Implementiert im bestehenden FastAPI-Dienst unter services/api/src/cve_api/status.
Der Collector verwendet die bestehende PostgreSQL-Jobinfrastruktur mit status_probe;
es entsteht kein zusätzlicher Container. Statusoberfläche: services/dashboard/src/status.

[Architektur](../../docs/architecture/statuspage-architecture.md),
[Collector](../../docs/status/collector.md), [API](../../docs/status/api.md).
Kein Docker-Socket, keine allgemeinen Remote-Kommandos und keine automatische Reparatur.
