# Interne Vertrauensgrenzen T00.02.04

Jeder Dienst hat eine eigene, widerrufbare interne Identität. Schreibende interne APIs benötigen
gegenseitig verifiziertes TLS und einen kurzlebigen, zielgebundenen Service-Nachweis (audience,
issuer, subject, expiry, zulässiger Jobtyp, Korrelations-ID). Das konkrete Signaturverfahren
wird vor Implementierung versioniert festgelegt; keine gemeinsam geteilten Admin-Tokens.
Gültigkeitsdauer höchstens 5 min, begrenzte Clock-Skew 30 s, Rotation und Replay-Schutz für
zustandsändernde Requests über idempotency_key. Keine Identität aus Request-JSON übernehmen.

Menschliche Actor-Information wird nur aus einer aktuell geprüften Sitzung delegiert, mit
Subject, Objektbereich und Berechtigung. Fachservice prüft Dienst und Actor; er vertraut
keinem beliebigen Header. n8n darf nur die Job-APIs aus der Netzmatrix anfordern, weder
Server noch Gruppen noch Benutzer administrieren. Event Dispatcher liefert ausschließlich
persistierte, typisierte Outbox-Ereignisse; deren Nutzdaten sind keine auszuführenden Befehle.

Nginx-Weiterleitung ist separat vertrauensgebunden (siehe ingress.md). Interner Netzwerkzugang
ist keine Autorisierung. Technische Upload-Identitäten, Dienstidentitäten und Benutzer-Sitzungen
sind getrennte Namensräume, Tokens werden niemals untereinander austauschbar akzeptiert.
Dashboard besitzt keine eigene universelle DB-Verbindung und keine vom Browser bestimmbaren Upstreams.

DB-Rollen je Fachkontext, keine SUPERUSER/CREATEROLE/CREATEDB/DDL-Rechte für Anwendungen.
DB-Owner/Migrationsrolle ist nicht Bestandteil einer Runtime-Verbindung. Keine pauschalen
public-Schemagrants, kein unkontrolliertes SET ROLE. TLS-verifizierte DB-Verbindungen,
Credentials pro Dienst mit Rotation; minimale SELECT-Sichten statt Zugriff auf Sicherheitsgeheimnisse.
api_ingest und inventory_processor besitzen keine UPDATE-/INSERT-/DELETE-Rechte auf
Serverstammdaten, Gruppen, Mitgliedschaften oder manuelle Sortierung.
Details: [DB-Matrix](../database/access-matrix.md).

Secrets werden als lokal restriktive, möglichst read-only Dateimounts bereitgestellt,
Schlüssel getrennt von PostgreSQL gesichert. Logs/Audit enthalten Referenzen, keine Tokens,
Passwort-Hashes, Rohinventare oder TOTP-Geheimnisse. Authentifizierungsfehler fail closed.
