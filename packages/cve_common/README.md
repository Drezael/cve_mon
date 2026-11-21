# cve-common 0.7.0

Reguläres Python-3.12-Paket mit py.typed, ohne Import-Nebenwirkungen und Fachlogik.
Installation über `make setup` (Entwicklung) oder gesperrte Runtime plus gebautes Wheel.
Enthält Settings/Secret-Lesen, PostgreSQL/Session/Transaktion, strukturierte Logs,
Kontext-IDs, HTTPX, Fehler, Health und Ressourcen-/Worker-Lebenszyklus.
Kein Zugriff auf andere Servicepakete und keine Import-Zeit-Verbindungen.

[Verwendung und Grenzen](../../docs/architecture/python-services.md).

Phase 7 ergänzt typisierte Jobs, Worker, Leases/Fencing und transaktionale Outbox
mit Dispatcher-/Consumer-Grundlage. [Architektur](../../docs/architecture/background-jobs.md).
