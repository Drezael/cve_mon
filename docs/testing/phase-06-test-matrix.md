# Phase-6-Testmatrix

| Bereich | Nachweis |
|---|---|
| Paket/Wheels | isolierte Offline-venv, pip check, Imports ohne Connect-Aufrufe, AST-Importgrenzen |
| Konfiguration | Pflichtwerte, Prioritäten, kein dotenv, Ports/Timeouts/Rollen/Hostnamen negativ |
| Secrets | fehlend/leer/öffentlich/Symlink/Directory/mehrzeilig/übergroß; sichere Fehler/Repr |
| FastAPI | Factory/Lifespan, technische Health, keine Docs/Fachrouten, Host/Methode/CORS negativ |
| HTTP-Identität | Forwarded/Clientheader entfernt, parallele UUIDs/ungültige IDs, keine Reflektion |
| Logging | JSON/UTC, Metadaten-Allowlist, Secretfelder, Credential-URLs und registrierte Werte |
| PostgreSQL | echte Readeridentität, keine Superuser-DDL/SET ROLE/Adminwrites, SQL/Rollback/Commit |
| Konkurrenz | unabhängige AsyncSessions, begrenzter Pool, Erschöpfung/Statementtimeout |
| Fehler/Recovery | falsches Passwort, nicht erreichbar, DB-Stop/Start, Liveness/Readiness getrennt |
| HTTPX | echter Loopbackserver, Readtimeout, Redirect nicht verfolgt, TLS falsch/korrekt, kein Env-Fallback |
| Worker | Stop-Event, Wiederholung, Cancellation, Teilstartfehler, keine Jobverarbeitung |
| Docker | Offline-Build, Python 3.12, Nicht-Root/Readonly/CapDrop, Netze/Ports/Mounts |
| Nginx | echte DNS-Verbindungsprobe aus Nginx; bisherige öffentliche Sperren in Regression |

`make check`, `make services-test`, `make services-security`, `make services-integration`.
Zusätzlich Regressionen `make infra-test db-test envoy-test postfix-test`.
Eigene UUID-Projekte mit privater PKI, Rollen und Datenvolume; Cleanup prüft Eigentümer.
Keine produktiven Secrets, keine zusätzlichen Infrastrukturkomponenten oder Fachmigrationen.
