# Sichere Jobausführung

Nur explizite Registry-Callables und versionierte, strikte Modelle; keine eval/exec-
oder Shell-/Importpfade aus Payloads. Rekursiv werden Secret-/Steuer-/URL-Felder
abgelehnt, insgesamt höchstens 16 KiB. Canonical-Request-Fingerprint schützt die
Idempotenz gegen unterschiedliche Anforderungen unter gleichem Schlüssel.

Native Funktionen prüfen Produzenten-/Handlerrolle, aktive Version, Typ-Limits und
Fencing. Direkte Änderungen verwalteter Datensätze sind verboten. Keine Superuser-
oder Migrationsidentität für Runtime. Alte Worker können weder Heartbeat noch Abschluss
oder geschützte DB-Effekte erfolgreich committen. Die normale Rollenberechtigung ersetzt
keine Lease; die Lease ersetzt umgekehrt keine fachliche Berechtigung.

Allgemeine Worker erhalten keine Gruppen-/Primärgruppen-/Sortierwrites. Solche
Fachlogik fehlt vollständig. Administrative Kontrolle ausschließlich im ausdrücklich
berechtigten API-Security-Kontext, ohne öffentlichen Endpunkt. Terminaler Job bleibt
terminal; Replay erzeugt neue Identität mit Herkunftsreferenz. Kein Reset der Versuche.

Fehlertexte werden nicht übernommen. Feste Codes und generierte neutrale Zusammenfassungen
verhindern Credential-/Payload-Leaks. Job-/Event-/Worker-UUIDs dürfen strukturiert geloggt
werden, Lease-Tokens und vertrauliche Daten nicht. Testhandler ausschließlich in tests.
