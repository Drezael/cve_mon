# Python-Dienstbetrieb

Liveness GET /health/live: Prozess antwortet ohne DB/Internet. Readiness GET
/health/ready: gestartete Ressourcen plus SELECT 1 mit eigener Identität und kurzem
Timeout, HTTP 200 oder 503. Beide ohne Cache und ohne Fachschreibvorgang. Docker
prüft Readiness auf Loopback; DB-Ausfall macht API nicht bereit, Liveness bleibt aktiv.
Ein Ausfall löst weder automatische Migration noch eine Passwort-/TLS-Abschwächung aus.

`make api-smoke-test`, `make services-integration`, Docker-Health und bereinigte Logs
prüfen. Häufige Ursachen: fehlende CVE_API_-Werte, private Dateirechte/UID, abgelaufene
DB-CA/Serverzertifikate, falscher Reader, Pool-/Statementtimeout. Keine kompletten DSNs,
Tokens, Cookies oder Bodies ausgeben. Request-/Korrelations-UUID zur Diagnose nutzen.
Nach Rotation/Rebuild `docker compose up -d --force-recreate cve-api` im ausgewählten
Projekt oder API stoppen/neu erstellen. Keine bestehenden Volumes löschen.

Sicherheitsrelevante Konfiguration wird vor Ressourceninitialisierung geprüft.
DB-Verbindungsfehler werden im Readiness-Ergebnis abgebildet, nicht mit internen
Fehlermeldungen offengelegt. Shutdown nimmt Readiness zurück und schließt Ressourcen;
bei fehlerhaftem Teilstart ebenfalls Cleanup. Keine fremden Docker-Projekte bedienen.
