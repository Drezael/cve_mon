# Administrative Serververwaltung

cve-api 0.10.0 registriert Server ausschließlich über POST dashboard/admin/servers mit
server:create, vollständiger MFA-Session, CSRF und frischer einmaliger Reauth. Eine zufällige
UUID entsteht in PostgreSQL, unabhängig von Anzeigename, Hostname oder IP. Der neue Server
hat keine Gruppen/Primärgruppe und wird global angehängt. Registrierung erzeugt weder
technische Inventare noch Jobs/Verbindungen zum Zielhost.

Pflicht request_id ist eine Client-UUID für Idempotenz pro Actor: dieselbe ID mit denselben
validierten Feldern liefert dieselbe Serveridentität; abweichende Felder ergeben 409.
Es werden keine Klartext-Requestbodies gespeichert, nur Digest und Serverreferenz. Jeder
erneute administrative Versuch benötigt erneut aktuelle Session/CSRF/Reauth.

Stammdaten: display_name, description, environment, criticality (low/medium/high/critical),
exposure (internal/restricted/internet_exposed/unknown). Phase 0 enthält kein bindendes
administratives Expositionsenum; diese vier Phase-10-Werte sind der ausdrückliche Vertrag.
Technische Hostidentitätsfelder dürfen bis zur späteren Inventarisierung beide NULL sein.
Die bestehende nichtleere Legacy-Paaridentität bleibt eindeutig, falls bereits vorhanden.
PATCH lehnt UUID, Status, Gruppen, Primärgruppe, Positionen, ACLs und technische Inventarfelder ab.

Objektmutationen benötigen ein starkes If-Match, etwa "3". GET/Mutation liefert ETag;
fehlend 428, syntaktisch/mehrdeutig 400, veraltet 412, fachlicher Konflikt 409. Vollständiger
Rollback einschließlich Reauthverbrauch, Audit und Outbox bei Fehlern. Kein automatisches
Wiederholen widersprüchlicher Befehle. Pydantic extra=forbid, 8-KiB-Ingresslimit und begrenzte
Textlängen gelten. Keine Oberfläche; Verträge unter contracts/api und contracts/inventory.
