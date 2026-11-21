# Implementierte Datenbankrechte Phase 3

Default Deny. Alle Runtime-Logins NOINHERIT/NOSUPERUSER/NOCREATEDB/NOCREATEROLE/
NOREPLICATION/NOBYPASSRLS; keine Owner-/Migrationsmitgliedschaft und kein CREATE/TEMP/TRUNCATE.
Neue Tabellen/Funktionen erhalten keine impliziten Runtime-Rechte. DDL in Revisionen
0008/00010 und Ergänzungen definiert die vollständige tabellen-/spaltengenaue Matrix.

| Rolle | Lesen | Schreiben |
|---|---|---|
| api_reader | Fach- und öffentliche Kontosichten, administrative Reihenfolge, Berichte | keines |
| api_ingest | Serveridentität, Snapshots/Receipts, expliziter Uploadkontext; authorize_upload-Funktion | Snapshot-/Receipt-INSERT, inventory.process anlegen, eigene Outbox/Audit |
| dashboard_admin | Server/Gruppen/Positionen, öffentliche Kontosicht | administrative Felder, Mitgliedschaften/Primärgruppe/Positionen, eigene Outbox/Audit |
| api_security | Securitytabellen und benötigte Server-/Gruppenidentitäten | Konten/Credentials/Grants/Sessions/MFA/Tokens, nur benutzerdefinierte Rollen, zugewiesene Job-INSERTs, Security-Outbox/Audit; invariants-Sperre |
| inventory_processor | Inventare/Serveridentität | nur Snapshot-Verarbeitungsfelder und normalisierte Inventartabellen; eigener Job, Outbox/Audit |
| importer | CVE-Daten/Quellen | CVE records/revisions, eigener Quellencursor/Job, Outbox/Audit |
| enricher | CVE-Daten/Quellen | neue Enrichments, eigene Quellencursor/Jobs, Outbox/Audit |
| matcher | Inventare/CVEs/Serverzustand | Matchingläufe/-belege, eigener Job, Outbox/Audit |
| findings_writer | CVEs/Matching/Server und eigene Findings | Findings/Historien/Risiko, eigener Job, Outbox/Audit |
| reporter | Fach-/Inventar-/Findingdaten ohne Authgeheimnisse | Berichte, eigener Job, Outbox/Audit |
| event_dispatcher | unveränderliche Outbox und Zustellungen | nur event_deliveries-Felder, notification.send anlegen, erlaubtes Audit |
| notification | Outbox, aktive Empfängersicht, eigener Job | Benachrichtigungszustellung, eigener Job, Audit |
| dashboard_preferences | eigene Präferenztabelle im Servicekontext | Präferenzen/version, Audit; keine administrative Reihenfolge |
| status_probe | CONNECT, SELECT 1/system.health | keines |
| n8n_app | ausschließlich n8n | dortige eigene Tabellen/Migrationen; kein CONNECT zu cve_monitoring |
| cve_migrator | Anwendungs-DB nach kontrolliertem SET ROLE | ausschließlich Migrations-/Wartungspfad zum NOLOGIN postgres_owner |

Authentifizierungsgeheimnisse sind api_security vorbehalten. api_ingest liest keine
API-Tokenverifikatoren, sondern erhält eine begrenzte Prüfantwort. RLS/Spaltengrants trennen
Jobtypen, Produzenten und Quellencursor. Outbox und historische Belege sind unveränderlich.
Audit bindet Schreiber und Aktion. Systemrollen/-permissions sind migrationsgeschützt.

Service-DB-Rollen bilden technische Grenzen, keine menschlichen Objektberechtigungen ab.
Die spätere API muss aktuelle Benutzer-/MFA-/Scopeprüfung und getrennte Pools implementieren;
kein Request darf den technischen Poolnamen auswählen. Objektfilter für Listen, Counts,
Exporte und Downloads bleiben obligatorisch. Eine vollständige Übernahme des API-Prozesses
kann dessen verfügbare Pools gefährden; dieses bestehende Restrisiko bleibt benannt.

Jeder wesentliche Login wird mit eigener Credentialdatei und verify-full-TLS tatsächlich
verbunden. Negativtests erfolgen nicht lediglich mit SET ROLE eines Superusers.
