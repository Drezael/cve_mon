# Automation-Laufzeitmigration

Alembic 00013_automation_runtime folgt linear auf 00012_original_identity. Alle zwölf
vorherigen Revisionen bleiben unverändert. Erweiterung ausschließlich in automation;
keine zusätzliche Jobdatenbank und keine Änderung von Inventar-/Gruppenrechten.
Bestehende jobs, job_attempts, event_outbox und event_deliveries bleiben erhalten.

Neue Felder: Version, Creator/Fingerprint/Korrelation, zufälliges Lease-Token, Heartbeat,
Ausführungs-/Gesamtdeadline, Cancel/Replay, Dauer und sichere Fehlerzusammenfassung.
Ergänzte Tabellen: delivery_targets, event_routes, delivery_attempts, event_consumers,
processed_events und runtime_actions. Keine Secrets/URLs in den Registriertabellen.
Zusätzliche partielle Indizes für fällige Jobs, Leases, Dead Letters, Entitäten und
Zustellungen; historische Daten bleiben aus aktiven Queue-Indizes ausgeklammert.

## Privilegierte enge Operationen

SECURITY DEFINER unter postgres_owner mit festem search_path=pg_catalog, qualifizierten
Objekten und ausdrücklich beschränktem EXECUTE. session_user bindet den realen
Caller, nicht frei wählbare GUCs/HTTP-Header. RLS aus Phase 3 bleibt bestehen.
Managed-Trigger verweigern direkte Laufzeitänderungen von Jobs, Versuchen, Events und
Zustellungen. Tabellenregistrierung nur über Migration/DBA, keine Runtime-DDL.
Fachschreibrechte bleiben bei den bestehenden dienstbezogenen Rollen.

## Bestandsdaten

runtime_version=0 kennzeichnet vorbestehende Phase-3-Datensätze. Sie bleiben byteinhaltlich
erhalten und werden nicht automatisch ausgeführt/versendet. runtime_version=1 wird
nur durch die geprüften Funktionen erzeugt. Metriken weisen offene Altjobs/Altevents
separat aus. Kontrollierte Übernahme erst mit gültigem Typvertrag/Handler und expliziter
Migration bzw. neuer referenzierter Anforderung; keine pauschale Reaktivierung.

## Rollback

Keine destruktive Down-Migration. Anwendungsdienst stoppen, Daten sichern und einen
geprüften datenhaltenden Migrations-/Restoreplan verwenden. Backups aus Phase 3 erfassen
auch sämtliche neuen Tabellen, Funktionen, ACLs und Historien; deren Regression wird
mit aktuellem Head erneut ausgeführt. Keine produktiven Volumes in Tests löschen.
