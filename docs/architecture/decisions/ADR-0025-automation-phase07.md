# ADR-0025 – Verwaltete PostgreSQL-Jobs und Outbox

Status: accepted. Datum: 06.11.2026.

Phase 7 erweitert die bestehenden automation-Tabellen mit Revision 00013. Laufzeitzeilen
versioniert; bisherige Zeilen bleiben ohne automatische Freigabe erhalten. Enge native
SECURITY-DEFINER-Operationen binden session_user, Token/Epoch, Zeit und Zustandsübergänge;
Trigger sperren direkte Runtimewrites. Alte breite Übergangs-CRUD-Pfade gelten nicht für
verwaltete Zeilen. Keine Erweiterung fachlicher Gruppenrechte oder zweite Queue.

Claims committen vor Ausführung/HTTP; Heartbeats/Recovery in eigenen kurzen Transaktionen.
Geschützte Business-Transaktionen prüfen Fence am Commitpfad. Consumer-ID/Effekt atomar,
externe Zustellung at least once. Reihenfolge nur für deklarierte Quell-Entitäts-Zielströme.
Fehlgeschlagene Zustellungen blockieren diese Folge bis ausdrücklich autorisierter Retry.
Zähler/Histories bleiben dabei erhalten, zusätzliche Versuche werden auditiert.

Default ohne Ziele/Handler. Allgemeine Worker sind Bibliothek, kein zusätzlicher generischer
Container. Eigenständiger Dispatcher mit privater HTTPS-Zielregistry und dedizierter Rolle.
Pakete/API-Kompatibilitätsimage 0.7.0; keine neuen externen Abhängigkeiten. Alternativen
Broker/Celery/Workflow-DAG und pauschale Exactly-once-Versprechen werden verworfen.
