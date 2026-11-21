# API-Konventionen T00.04.01

OpenAPI 3.1.0, JSON UTF-8 und /api/v1; Breaking Changes erhalten neue API-/Schemaversion.
UUID-Identitäten sind unveränderlich, Zeiten RFC3339 mit Zeitzone, intern UTC. Keine
geheime Information in URLs. Unbekannte Request-Felder und doppelte JSON-Keys ablehnen.
Responses enthalten keine Passwort-Hashes, Tokenverifikatoren, MFA-Secrets oder Rohfehlermeldungen.

Fehler als application/problem+json: type (URN), title, status, code, request_id und optional
sanitierte detail/errors (JSON-Pointer ohne eingegebenen Secretwert). Kein HTML-Stacktrace.

| HTTP | Bedeutung |
|---|---|
| 200 / 201 / 202 / 204 | Gelesen/dupliziert, erstellt, dauerhaft angenommen, ohne Body erfolgreich |
| 400 | Nicht parsebares JSON oder ungültiger Requestaufbau |
| 401 | Fehlende/ungültige Identität |
| 403 | Fehlende Berechtigung, CSRF- oder MFA-Nachweis |
| 404 | Nicht vorhanden oder Objektzugriff nicht erlaubt; keine Existenzoffenlegung |
| 409 | Fachkonflikt, inaktiver Server, letzter Administrator, doppelte ID mit anderem Inhalt |
| 412 / 428 | If-Match veraltet / bei konkurrierender Änderung erforderlich |
| 413 / 415 / 422 | Zu groß / falscher Medientyp / Vertrags- oder fachlicher Validierungsfehler |
| 429 | Rate-Limit, Retry-After erforderlich |
| 500 / 503 | Sanitierter interner Fehler / vorübergehend nicht verfügbar |

Listen: limit 1–200 (Default 50), opaque cursor und next_cursor. Stabile Ordnung nach
fachlichem Sortierwert plus UUID, feste Snapshotgrenze im Cursor; keine Offset-Doppelungen.
Filter/Suchbegriffe sind begrenzt und parametrisiert, keine freien SQL-Feldnamen.
CVE-Suche unterstützt q, sonst ist nur die im jeweiligen Endpunkt spezifizierte Auswahl zulässig.
Unbekannte Queryparameter ablehnen, besonders an der Statuspage; keine beliebigen Sortierspalten.

Mutable Ressourcen liefern einen starken ETag auf Basis der version. PATCH/PUT/DELETE und
administrative Lebenszyklusaktionen benötigen If-Match; create und Tokenwiderruf sind separat
idempotent definiert. Änderung und Versionsinkrement atomar; stale 412, fehlender Header 428.
Sortierung ersetzt eine vollständige, eindeutige Permutation eines berechtigten Aggregats;
Teiländerungen und veraltete Mitgliedschaften ergeben Konflikt statt stiller Vermischung.

Inventar-idempotenz steht im [Annahmevertrag](../../contracts/inventory/rejection-cases.md).
Interne Jobanforderungen deduplizieren idempotency_key je Jobtyp/Actor. Ein HTTP-202 bedeutet
persistente Annahme, keine abgeschlossene Fachverarbeitung. Keine stillen Retries nicht
idempotenter Writes. Korrelations-ID serverseitig prüfen/erzeugen und durch Outbox weiterreichen.

Limits gemäß ingress.md, zusätzlich je Identität in der API erzwingen. Dokumentation aus OpenAPI
nur kontrolliert intern/angemeldet veröffentlichen, keine öffentlich erreichbaren Admin-Schemas
als Ersatz für Zugriffsschutz. Das Vertragsdokument im Repository bleibt versionierbar.

Standardgrundlage: [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html).
