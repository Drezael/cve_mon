# Jobs, Outbox, Audit und technische Daten

`automation.jobs` speichert UUID, job_type, status, priority, created_at/scheduled_at,
started_at/finished_at, max_attempts/attempts, lease_owner/lease_until, fencing_token,
error_code, result_reference, begrenzte Referenzpayload, entity_id, actor_user_id,
actor_reference und idempotency_key. UNIQUE(job_type,actor_reference,idempotency_key).
Zustände: pending, queued, running, succeeded, failed, retry_pending, cancelled, timed_out.
Running benötigt Owner und Lease; Versuche und Zeitreihenfolge sind geprüft.
`job_attempts` historisiert Versuch/Worker/Fencingtoken/Zeiten/Ergebnis eindeutig je Jobversuch.

Versionierter job_types-Katalog bindet jeden Typ an genau einen Handler und erlaubte Produzenten:
inventory.process, cve.import, cve.enrich, matching.run, findings.reconcile, report.generate,
notification.send. FORCE RLS filtert Handler-/Produzentenzugriffe nach tatsächlichem current_user.
Spaltengrants verhindern Runtime-Änderungen an Typ, Originalpayload und Identität.

Claims verwenden Transaktionen und `FOR UPDATE SKIP LOCKED`, Priorität und scheduled_at.
Übernahme erhöht attempts/fencing_token, Lease 120s und Heartbeat 30s sind die geplante
Workerpolicy. Reclaim abgelaufener Leases erhöht den Token erneut; Abschluss und Heartbeat
müssen Owner, Token und aktuelle Lease bedingt vergleichen. Die SQL-Tests zeigen disjunkte
Claims und abgewiesene alte Abschlüsse. Vollständige Worker/Backoff/Heartbeats folgen Phase 7;
kein Exactly-once-Versprechen und keine externe Queue.

`event_outbox` hält unveränderliche Ereignisidentität, Typ/Quelle, Aggregate, Zeit,
correlation_id, idempotency_key und begrenzte Referenzpayload. UNIQUE(source,idempotency_key).
Ereignistypen und Quellen sind an den produzierenden DB-Login gebunden. Typen:
inventory.accepted/inventory.processed/cve.imported/cve.enriched/matching.completed/
finding.changed/report.ready/security.changed/administration.changed.
Fachänderung und Outbox-INSERT werden gemeinsam committed oder zurückgerollt.

`event_deliveries` trennt die Zustellung vom Originalereignis: PK(event_id,destination),
status pending/running/delivered/retry_pending/failed, attempts, next_attempt_at,
Lease/Owner/Fencingtoken, delivered_at und last_error_code. event_dispatcher darf
Ereignisse nur lesen und ausschließlich Zustellmetadaten schreiben; niemals Payload ändern.
`notification_deliveries` dedupliziert event_id/Empfänger/Kanal, mit Status,
message_id, Versuchen und Fehlercode. SMTP-Annahme accepted beweist keine endgültige Zustellung.
n8n bekommt später stabile Event-IDs; es erhält niemals Fachdatenbankrechte.

`security.audit_log` ist append-only mit Actor, source_role, Aktion, Objekt, request_id,
Zeit, Ergebnis und bereinigten Metadaten. INSERT-RLS bindet Quelle und Aktion an die tatsächliche
Rolle über audit_actions. `login_events` und `user_events` ergänzen Security-Historien.
Schlüssel wie password/token/authorization/cookie/totp_secret werden rekursiv abgewiesen;
Payload-/Metadaten sind auf 64 KiB begrenzt. Freitexte können keine beliebige Geheimniserkennung
leisten: spätere Dienste dürfen nur bekannte Codes und sanitierte Werte einsetzen, nie
Rohinventare, Credentialwerte oder SQL-Fehlertexte. Audit-/Outbox-Rollback ist atomar testbar;
die API-Phase muss für Verwaltungswrites einen Audit-Commit zwingend mitführen.

`dashboard.user_preferences` speichert persönliche Einstellungen und version getrennt von
administrativer Sortierung. Eigene Runtime-Rolle dashboard_preferences ohne Server-/Gruppenwrites.
Die spätere API prüft die Sitzung und darf keine fremde user_id aus einem Request übernehmen.
`system.reports` speichert Anforderer, autorisierten Serverscope, Format, Job, Status,
Inhalt/Storageverweis, Hash und Zeiten; Reporter schreibt, API liest nach aktueller Autorisierung.
`source_sync_state` hält Cursor/ETag/Zeiten/Fehler je Quelle; FORCE RLS trennt Importer/Enricher.
`settings` enthält ausschließlich nicht geheime technische Konfiguration ohne Runtime-Writes.
`invariant_locks` stellt transaktionale Sperrpunkte bereit; `health` ist eine minimale Lesesicht.
Keine Docker-/Live-Status- oder n8n-internen Tabellen werden vorgezogen.
