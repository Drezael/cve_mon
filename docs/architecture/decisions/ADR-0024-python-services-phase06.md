# ADR-0024 – Installierbare Python-Servicebasis

Status: accepted. Datum: 06.11.2026.

Kontext: Phasen 0–5 stellen Verträge, Werkzeuge, PostgreSQL, Ingress, Egress und
SMTP bereit. Phase 6 benötigt technische Anwendungsbausteine ohne vorgezogene Fachlogik.

Entscheidung: cve-common/cve-api 0.6.0 als getrennte src-Pakete, Python 3.12,
FastAPI-Lifespan, SQLAlchemy/Psycopg asynchron, Pydantic Settings, HTTPX. Keine
Schemaänderung oder Privilegienausweitung. cve-api initial nur api_reader; weitere
Identitäten erst explizit für autorisierte spätere Fachaufgaben. Eine Session pro
Arbeitskontext und explizite Transaktionen, begrenzte Pools, kein Auto-Migrate.

Root-pyproject bleibt Werkzeugkonfiguration. Runtime-/Dev-Locks und Offline-Wheels
statt zufälligem PYTHONPATH oder paketiertem Monolithen. Nginx-Kommunikation wird
intern geprüft, öffentliche Routesperren bleiben aktiv. Kein öffentliches API-Schema
oder Header-Scheinauthentifizierung. Keine zusätzliche Infrastruktur.

Alternativen: globales Sammelpaket aller Fachservices, globale privilegierte DB-Session,
Worker als vorgezogene HTTP-Fachservices verworfen wegen Kopplung und Rechteausweitung.

Folgen: Bootstrap installiert zwei lokale Pakete. Compose-Validator erlaubt genau
fünf implementierte Dienste. Frühere Vor-Phase-6-Prüfung auf keinerlei Python-Dateien
in services wird auf ausschließlich die technische API präzisiert. DB-/Fachverträge
und Postfix bleiben unverändert.
