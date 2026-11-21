# cve-event-dispatcher 0.7.0

Eigenständig installierbares Python-3.12-Paket unter src/cve_event_dispatcher.
Start: `python -m cve_event_dispatcher.main`, Factory `main:create_app`.
Konfiguration über CVE_DISPATCHER_, private Registry und Passwort-/CA-Dateien.
PostgreSQL-Identität ausschließlich event_dispatcher. Keine Import-Zeit-Verbindungen.

Begrenzter Outbox-Loop mit kurzen Reservierungstransaktionen, Leases, Heartbeats,
Fencing und persistenter Zustellhistorie. Authentifiziertes HTTPS an ausdrücklich
autorisierte interne Ziele; standardmäßig leere Registry. Keine Fachhandler.
Nur interne /health/live, /health/ready und /metrics; kein öffentlicher Hostport.

Nicht-Root, readonly, begrenzte Ressourcen, nur cve_internal/cve_data und eigener
privater readonly-Mount. SIGTERM drainiert begrenzt; Lease-Recovery nach Absturz.
[Betrieb](../../docs/operations/event-dispatcher.md),
[Architektur](../../docs/architecture/transactional-outbox.md),
[Abnahme](../../docs/development/phase-07-acceptance.md).
