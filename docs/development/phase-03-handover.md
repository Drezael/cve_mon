# Phase-3-Übergabe

Die Datenbankgrundlage besteht aus PostgreSQL 18.6, getrennten Datenbanken `cve_monitoring`
und `n8n`, acht Fachschemas, einer linearen expliziten Alembic-Kette, NOLOGIN-Ownern und
minimalen Runtime-Rollen. Keine API, Loginfunktion, Worker, n8n-Interna oder Dashboardlogik
wurde vorzeitig implementiert. Die Originalkonzepte bleiben unverändert.

## Übernahme

[Start/Migration/Betrieb](../deployment/postgresql.md),
[Backup/Restore](../operations/postgresql-backup-restore.md),
[Modell](../database/overview.md), [Rechte](../database/access-matrix.md),
Plan (nur lokal archiviert), [Aufgabenstatus](phase-03-status.md), [Abnahme](phase-03-acceptance.md).
Nächster angeforderter Entwicklungsschritt ist Phase 4 (Envoy); der Beginn ist ein eigener Auftrag.

## Auswirkungen auf vorhandene Phasen

Phase 1: drei neue exakt gesperrte Bibliotheken samt transitiven Hashes; Mypy prüft jetzt auch
Migrationen. Pytest trennt daemonfreie Standardprüfungen, infrastructure und database.
Makefile/CI/Repositoryvalidator kennen DB-Befehle und Pflichtdateien; die Baseline bleibt leer.
Phase 2: Compose enthält PostgreSQL ausschließlich auf cve_data ohne Hostports. Dessen
kanonisches Modell und Negativvalidierung sind erweitert. Nginx-Up und seine Tests starten
explizit nur Nginx; TLS-/Routing-/Netzverträge bleiben mit echten Docker-Tests geprüft.
Keine fremden Container, Volumes, Ports oder Firewallregeln verändert.

Phase 0: ADR-0021 und OpenAPI 1.1.0 dokumentieren vor Implementierung einer Fach-API den
Status-/Rollen-/Outboxabgleich. Logische und physische Tabellennamen sind explizit abgebildet.
Sortierwerte sind einmalig an Gruppen/Mitgliedschaften gespeichert, nicht doppelt synchronisiert.
Gruppenrechte vermitteln Lesen; Uploads bleiben direkte Serverfreigaben.

## Verbindliche Anschlussregeln

- Phase 6: getrennte kleine Pools pro DB-Kontext, verify-full-TLS und ausschließlich eigene
  Credentialdateien mounten. Kein dynamischer Rollenname aus Requests, kein Owner im Runtimepool.
- Phase 7: SKIP LOCKED, begrenzte Versuche/Backoff, Lease/Heartbeat und bedingte Fencingabschlüsse
  implementieren. Fachänderung, Jobzustand und Outbox soweit möglich atomar committen.
- Phase 8/9: Argon2-Kosten/HMAC, sichere Cookies/CSRF, TOTP-AEAD mit externem key_id, Replay- und
  Sessionwiderruf, MFA-Adminpflicht und Letzter-Admin-Transaktion auf invariant_locks ergänzen.
  Keine Standardkonten vorhanden; ersten Admin ausschließlich lokal autorisiert einrichten.
- Phase 10: If-Match/Version und gesperrte Sortieraggregate, vollständige autorisierte Permutationen,
  Scopeprüfung ungruppierter Server, Archivierungsregeln und Audit atomar implementieren.
- Phase 11: vollständigen JSON-Schema-/Duplikat-/Zeit-/Serverrechtcheck ergänzen. Identischer
  inventory_id/Hash-Konflikt ist idempotent, veränderter Inhalt Konflikt. Snapshot, Receipt,
  inventory.process-Job und inventory.accepted-Outbox in einer Transaktion.
- Phase 14: erst nach vollständiger Bereichsnormierung processed setzen. Partial liefert positive
  Zusatzbeobachtungen; fehlende Bereiche niemals als leere erfolgreiche Bestände behandeln.
- Phase 15–18: Matching auf lokalem CVE-/Quellenstand, volle Versionsstrings, reproduzierbare
  Quellen-/Regelrevisionen, stabile Findings und begründete Historie; keine Archivierungsentwarnung.
- Phase 19: n8n führt nur seine eigenen regulären Migrationen aus. Encryption-Key separat sichern,
  Ereignisse anhand stabiler IDs deduplizieren, keine direkte Fachdatenbankverbindung einführen.
- Phase 20/21: persönliche Präferenzen von administrativen Positionen trennen, aktuelle Benutzer-
  und Objektgrants bei Listen/Counts/Exports erneut prüfen.
- Phase 22: status_probe nutzt ausschließlich minimale Verfügbarkeitsprüfung. Inventarisierte
  Dockerzustände sind historisch und keine Live-Dienstprüfung; kein Docker-Socketzugriff.

Die DBA-Werkzeuge führen keine stillen Resets, Major-Upgrades oder produktiven Restores aus.
Der Entwicklungsstack wird nach der Prüfung gestoppt; Datenvolume und lokale Credentials bleiben
für die Folgephase erhalten. Testprojekte werden ausschließlich anhand eigener Präfixe/Labels bereinigt.
