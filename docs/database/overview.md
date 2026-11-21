# Physisches Datenmodell ab Phase 3

PostgreSQL 18.6 enthält die Datenbanken `cve_monitoring` (Owner postgres_owner) und `n8n`
(Owner n8n_owner). Beide Owner sind NOLOGIN. `cve_migrator` besitzt ausschließlich den
kontrollierten SET-ROLE-Pfad zum Anwendungsowner. Runtime-Logins sind keine Owner.

DDL-Wahrheit ist die lineare, transaktionale [Alembic-Konfiguration](../../database/alembic.ini) mit der Kette unter database/migrations/versions.
Die acht Fachschemas sind `inventory`, `cve`, `matching`, `findings`, `security`, `automation`,
`dashboard`, `system`. `public` enthält nur Alembics Versionstabelle; n8n erhält lediglich
seine leere eigene Datenbank und die dortigen CREATE-Rechte für seine späteren Migrationen.

UUID-PKs verwenden gen_random_uuid, Zeitpunkte timestamptz/UTC, rohe Versionszeichenfolgen
text, originale Quellen JSONB plus Inventarbytes. Fremdschlüssel sind grundsätzlich RESTRICT,
keine historischen Kaskadenlöschungen. Komposit-FKs binden Primärgruppen, Snapshot-/Server-,
Matching-/CVE- und Finding-/Komponentenreferenzen. Fachliche CHECKs und UNIQUEs werden mit
realem PostgreSQL geprüft. Dynamische JSON-Fakten ersetzen keine administrativen Stammdaten.

Optimistische Versionen verlangen beim Update `OLD.version+1` und unveränderte UUID/created_at.
API-Phasen müssen zusätzlich `WHERE version=:if_match` und Rowcount prüfen; ein automatisch
hochgezählter Wert allein erkennt keine veraltete Benutzeransicht. Transaktionen sperren
zugehörige Server-/Gruppen-/Reihenfolgeaggregate in stabiler Reihenfolge.

Sprachkonventionen und Namensabbildung zum Phase-0-Entwurf:

| Logischer Entwurfsname | Implementierung |
|---|---|
| Server state / hostname | servers.status / inventory_hostname, zusätzlich inventory_name |
| Benutzer normalized_username / state | username_normalized / status |
| Snapshot inventory_id als interner PK | snapshots.id interner PK, inventory_id separate globale UNIQUE-Identität |
| os_observations | operating_systems; Kompatibilitätssicht os_observations |
| group_order / server_order | kanonische Positionsfelder; abgeleitete Dashboard-Sichten |
| findings.records / history | findings.findings / status_history; lesende Kompatibilitätssichten |
| automation.outbox | event_outbox; lesende Kompatibilitätssicht |
| system.audit_events / source_sync / invariants | security.audit_log / system.source_sync_state / invariant_locks; lesende Sichten |
| Account pending / Finding acknowledged / Match unknown | pending_activation / under_review / not_evaluable |

Neue Fachschreiber verwenden die kanonischen Tabellen mit expliziten Grants; Alias-Sichten
sind keine zusätzlichen Runtime-Schreibwege. Keine DDL verwendet Benutzerrequest-Inhalte.

[Server/Gruppen](server-and-groups.md), [Inventar](inventory.md), [CVE/Matching/Findings](cve-and-findings.md),
[Security](security.md), [Jobs/Audit](automation-and-audit.md), [Rechtematrix](access-matrix.md),
[Betrieb](../deployment/postgresql.md), [bewusste Vertragspräzisierung](../architecture/decisions/ADR-0021-postgresql-phase03.md).
