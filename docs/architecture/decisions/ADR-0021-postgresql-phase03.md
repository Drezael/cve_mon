# ADR-0021: PostgreSQL-Implementierung und Vertragsabgleich Phase 3

Status: accepted  
Datum: 06.11.2026  
Anforderungen: T03.01–T03.09; konkretisiert ADR-0001/0003/0004/0013–0017.

## Kontext und Problem

Das Phase-3-Konzept verlangt konkrete Felder, sechs Matchingzustände, sieben Findingzustände
und vier Standardrollen. Der logische Phase-0-Entwurf verwendete teilweise andere Namen und
separate Sortiertabellen. Doppelte administrative Wahrheiten würden auseinanderlaufen.

## Entscheidung

PostgreSQL 18.6 aus dem offiziellen, per Digest fixierten Bookworm-Image; Datenvolume am
versionsübergreifenden Elternpfad `/var/lib/postgresql`, PGDATA `/var/lib/postgresql/18/docker`.
Acht Fachschemas, separate n8n-Datenbank. Alembic führt explizite PostgreSQL-DDL transaktional
unter Advisory-Lock aus. NOLOGIN-Owner; Runtime-Logins mit expliziten Tabellen-/Spaltengrants
und FORCE RLS auf gemeinsamen Job-, Outbox-, Quellen- und Systemrollenbereichen.

Kanonische Gruppenposition ist `server_groups.sort_order`, kanonische Mitgliedsposition
`server_group_memberships.display_order`. Dashboard-Order-Sichten lesen diese Werte;
ungegliederte Server besitzen eigene Positionen. Versionsaggregate bleiben getrennt.
Dies ersetzt die physischen separaten Ordertabellen aus dem logischen Entwurf in ADR-0015,
erhält aber Datenhoheit, globale Gruppenfolge und gruppenabhängige Serverfolge.

Phase-3-Zustände sind verbindlich: `pending_activation`, `under_review` statt `acknowledged`,
`not_evaluable` statt unpräzisem Matching-`unknown`; weitere Zustände gemäß DDL und OpenAPI 1.1.0.
Administrator, Benutzeradministrator, Security Analyst und Viewer ersetzen die alte
Dreierliste mit Operator. Technische und implizite Login-Scopes sind keine menschlichen RBAC-Seeds.
Outboxtypen unterscheiden `cve.imported` und `cve.enriched`; Annahme heißt `inventory.accepted`.
Server-Anlage/Antwort ergänzen inventory_name und administrative Metadaten, Benutzeranlage/-antwort
die verpflichtende E-Mail-Adresse passend zu den Phase-3-Pflichtspalten. API-hostname bildet
inventory_hostname ab; API-Verarbeitungszustände bilden pending/processing/processed auf
queued/running/succeeded ab. Diese Präzisierung ersetzt ältere Namen vor der ersten Implementierung einer Fach-API;
`unknown` bleibt als Risiko- und Live-Statuswert zulässig.

Gruppenfreigaben vermitteln Leserecht. Uploads benötigen zusätzlich ein explizites direktes
Serverrecht; Gruppenänderungen erweitern keine Upload-Allowlist. Technische Tokens benötigen
Server-Allowlist und gebundene Zertifikats-SAN. `api_ingest` liest keine Tokenverifikatoren,
sondern darf ausschließlich die begrenzte `security.authorize_upload`-Prüffunktion ausführen.

## Alternativen und Begründung

ORM-Autogenerierung, globale Service-Ownerrechte, Trust-Netzauthentifizierung und veröffentlichte
DB-Ports würden die vorgegebenen Prüf- und Isolationsgrenzen schwächen. Doppelt persistierte
Sortierwerte erzeugen vermeidbare Synchronisationsfehler. Vollständige Benutzer-/Workerlogik
bleibt in den vorgesehenen Folgephasen.

## Auswirkungen und Nachweise

[Physisches Modell](../../database/overview.md), [Zugriffsmatrix](../../database/access-matrix.md),
[Betrieb](../../deployment/postgresql.md), [Abnahme](../../development/phase-03-acceptance.md).
Originale unter dev_docs bleiben unverändert. Versionierte Migrationen und ihre Seeds sind
DDL-Wahrheit; Textdokumente erklären Zuständigkeiten und die bewussten Namensabbildungen.

Quellen: [offizielles Image](https://hub.docker.com/_/postgres),
[PostgreSQL-Versionierung](https://www.postgresql.org/support/versioning/),
[Unicode-Normalisierung und casefold](https://www.postgresql.org/docs/18/functions-string.html),
[Alembic-Verbindung/Transaktion](https://alembic.sqlalchemy.org/en/latest/cookbook.html).
