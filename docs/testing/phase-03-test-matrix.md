# Phase-3-Testmatrix

| Gruppe | Ausführung | Wesentliche Nachweise |
|---|---|---|
| Daemonfreie Schutzgrenzen | make check | Secretrechte/-Form/Symlinks, Produktionsgenerierung gesperrt, Löschschutz, lineare Migrationen, Hashlock, OpenAPI/JSON/YAML, Baseline |
| Tatsächliche Rollenlogins | make db-security-test | alle 16 Anwendungslogins mit eigenen Passwörtern/TLS, n8n-DB-Isolation, kein Runtime-DDL/TEMP/Ownerwechsel, kein unberechtigter Credential-/Adminzugriff |
| Netzwerk/Prozess | make db-test | nur cve_data, kein Portbinding, persistentes Elternvolume, UID999, effektive Capabilities0, read-only, Health und Head |
| Administrationsintegrität | make db-test | normalisierte Eindeutigkeit, UUID/Version, mehrfaches Membership, verzögerter Primärgruppen-FK, atomarer Positionswechsel |
| Inventare | make db-test | aktive Registrierung, unveränderliche Bytes/Hash/Identität, doppelte ID, verbotene Gruppenfelder, ältere Uploads/Partial/Qualität, rohe Paketversionen/Architekturen |
| CVE und Findings | make db-test | CVE-ID, Revisionen/Provenienz, gleiche-CVE-Referenz, mehrere installierte Versionen, stabile Findingidentität, Historie und keine Archivierungsentwarnung |
| Security | make db-test | Unicode-Konten, Zustände/FKs, vier geschützte Standardrollen, keine Standardbenutzer, Sessions/MFA/Recovery/Tokenconstraints, keine Uploadvererbung aus Gruppen |
| Shared Tabellen | make db-test | Jobtyp-RLS und Spaltenrechte, Outbox-Rollback/Deduplizierung/Quellenbindung, Payload unveränderlich, Auditaktionsbindung und reservierte Secretkeys |
| Konkurrenz | make db-test | echte gleichzeitige Verbindungen mit gehaltenen Locks, disjunkte Job-/Deliveryclaims per SKIP LOCKED, abgelaufene Lease und alter Fencingabschluss, Versionskonflikte und doppelte Inventar-ID |
| Migrationen | make db-test | erster Schritt/Head/leeres Volume, Wiederholung, Provisionierung ohne Passwortreset, fehlerhafte DDL und tatsächliches pg_cancel_backend rollen vollständig zurück |
| Persistenz | make db-test | vollständiger Datenfingerprint vor/nach Restart und Force-Recreate mit bestehendem Volume |
| Query-Pläne | make db-test | 3000 synthetische Snapshots mit Historyindex; Paketidentitätsindex verwendbar, keine nicht belegte Last-/Skalierungszusage |
| Sicherung/Wiederaufbau | make db-test | beide Datenbanken/Globals, geschützte Dateien, Quelle gestoppt, neues Zielvolume, vollständiger Daten-/Rechte-/Strukturvergleich, Hashmanipulation verweigert |
| Phase-2-Regression | make infra-test | 40 reale Nginx/TLS/mTLS/Reload/Limit-/Netzwerkprüfungen bei erweitertem Compose |

Explizite Datenbanktests werden ohne Daemon oder passende Berechtigung fehlschlagen; kein stiller
Skip. Lokaler Dockerzugang hier über autorisiertes `CVE_DOCKER_SUDO=1`. Tests brauchen keine
DB-Hostports und starten keine zukünftigen Fachservices. Ein gehosteter CI-Lauf ist erst nach
Veröffentlichung möglich; dieselben Befehle sind im Workflow eingetragen.
