# cve-api 0.19.0

Installierbares Python-3.12-Paket: Factory/Lifespan, interne Healthchecks, lokale Auth/MFA,
Benutzer/Rollen/ACL, Server-/Gruppenverwaltung und persistente Inventarannahme.
Start: python -m cve_api.main. Vier explizite Pools: api_reader, api_security,
dashboard_admin und api_ingest. Keine dynamische Rollenwahl, keine Ressourcen beim Import.
Gemeinsame technische Bibliothek und Dispatcher bleiben 0.7.0.

Dashboardzugang nutzt private Ingress-Capability, vollständige Session/MFA und Origin/CSRF.
Technische Uploads nutzen separates Ingress-Gate, mTLS und server-/client-/zertifikatsgebundene
Tokens. Beide Wege teilen Schema, begrenzten Parser und unveränderliche Annahme. 202 bestätigt
accepted nach Commit, einschließlich idempotenter Retries. Keine Jobs oder Snapshots vor
Phase 14. Laufzeitabhängigkeiten enthalten hashgesichertes JSON Schema und Multipart.

[Uploadarchitektur](../../docs/architecture/inventory-upload.md),
[Inventarbetrieb](../../docs/operations/inventory-upload.md),
[Verwaltung](../../docs/architecture/server-management.md),
[Authentifizierung](../../docs/architecture/authentication.md).

Phase-12-Kompatibilität: API 0.11.1 unterstützt zusätzlich den gemeinsamen Vertrag 1.1
(Hardware, RPM-Details, Dienstmanager und lokale Docker-Images). 1.0 bleibt unverändert.
Revision 00018 erweitert nur die Versionsfreigabe; Annahme und Sicherheitsgrenzen bleiben
bestehen. [Entscheidung](../../docs/architecture/decisions/ADR-0030-inventory-collection-phase12.md).

Phase 18 ergänzt `/api/v1/findings` auf dem bestehenden geschützten Dashboard-Origin.
Objekt-Scope, CSRF, aktuelle Berechtigungen und ETags gelten auch für Finding-Aktionen.
[API-Vertrag](../../contracts/api/finding-management.openapi.yaml),
[Sicherheit](../../docs/security/finding-management-security.md).

Phase 19 ergänzt `/api/v1/dashboard/notifications`: persönliche Historie, Präferenzen und
privilegierte Regel-/Templateverwaltung. [Vertrag](../../contracts/api/notification-management.openapi.yaml).
