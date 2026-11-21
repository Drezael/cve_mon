# Geschützte Status-API

/api/v1/status/overview, services, pipelines, incidents und maintenance sind ausschließlich über den vorhandenen verifizierten Nginx-/Sessionweg erreichbar. deployment:status:read ermöglicht eine minimierte Übersicht; deployment:diagnostics:read erlaubt Details, Checkmetriken und Historien; deployment:maintenance:manage erlaubt ausschließlich Wartungsmetadaten. Die beiden neuen administrativen Rechte sind explizit im bestehenden Katalog und nur der Systemrolle Administrator zugeordnet. Analysten behalten ihren vorhandenen minimierten Statuszugriff, Viewer erhalten keinen neuen Grant. Historien: limit 1–100, offset bis 100000, Stunden 1–744, maximal 2000 Messpunkte; Filter-Allowlist. Kein öffentliches Statusangebot und kein Probe-/URL-/SQL-/Shell-Endpunkt. no-store und bestehende CSP bleiben wirksam. Ein separater technischer Probe-Key schützt die schmale Nginx-API-Readinessprüfung; er erzeugt keine menschliche Sitzung.


Die Übersicht enthält zusätzlich `control`: Aktivierung, aktuellen Zustand des
zentralen Queue-Consumers, dessen letzten Kontakt sowie wartende, beanspruchte,
pausierte und fehlgeschlagene Nachrichten. Diese Werte werden unabhängig von der
letzten persistierten Collector-Messung gelesen.

`POST /api/v1/status/services/{id}/restart` verlangt
`deployment:service:restart`, Session, CSRF, `Idempotency-Key` und `{reason}`.
HTTP 202 bestätigt ausschließlich den dauerhaften Queue-Auftrag. Der tatsächliche
Neustart erfolgt erst nach n8n-Freigabe. `GET /api/v1/status/admin/restarts` liefert
die feste Zielauswahl und maximal 25 Ausführungsstände ohne Lease-Geheimnisse.
[Details und Grenzen](../operations/microservice-restarts.md).
