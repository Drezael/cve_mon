# Phase-6-Abnahme

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge und 54 Abnahmepunkte erfüllt.**

622 Tests bestanden: 270 Standardtests (81 neue Service-Unit-/ASGI-/HTTP-Tests),
10 Service-Integrationstests, 40 Infrastruktur-, 189 PostgreSQL-, 77 Envoy- und 36 Postfix-Tests.
`make check`, `make setup python-check` und frische Offline-Wheel-Installation erfolgreich.
Mypy: 108 Quelldateien, Ruff/Format grün, beide Compose-Modelle und alle Verträge gültig.
Secret-Scan mit unveränderter Baseline erfolgreich. Keine Original-Phasenvorgaben verändert.

Paketversion cve-common/cve-api 0.6.0. Lokale API, PostgreSQL, Envoy und Postfix gesund.
Die vier fremden Nextcloud-Container sind unverändert. Fachendpunkte bleiben geschlossen.

## Verpflichtende Abnahme

| Nr. | Prüfung | Nachweis |
|---|---|---|
| 1 | Python 3.12 wird verwendet. | Host-/Container-Version geprüft; Python-Digest |
| 2 | Gemeinsames Paket vorhanden. | packages/cve_common/src/cve_common |
| 3 | Gemeinsames Paket installierbar. | Frische Offline-venv und make setup |
| 4 | Gemeinsames Paket importierbar. | Isolierte Wheel-/Importprüfung |
| 5 | Keine Ressourceninitialisierung beim Import. | test_installed_packages_import_without_resources |
| 6 | Python-Abhängigkeiten reproduzierbar. | Runtime-/Dev-Locks mit Hashes, Offline-Dockerbuild |
| 7 | FastAPI-Grundstruktur vorhanden. | services/api/src/cve_api |
| 8 | App Factory funktionsfähig. | Factory und ASGI-HTTP-Tests |
| 9 | Lifespan funktioniert. | test_stop_and_repeated_lifespan; echte API-Starts |
| 10 | Ressourcen werden beim Shutdown freigegeben. | Teilstartfehler, Cancellation, Docker-Neustart |
| 11 | Konfigurationsvalidierung funktioniert. | Negative Settings-Tests |
| 12 | Dienstspezifische Konfiguration funktioniert. | ApiSettings vs ServiceSettings, unabhängige Präfixe |
| 13 | Secrets werden geschützt geladen. | O_NOFOLLOW/fstat/private Modes; negative Dateiarten |
| 14 | Fehlende Secrets werden erkannt. | Missing/empty/symlink Tests |
| 15 | Keine Secrets in Logs. | Logging-Marker, native Containerlogs ohne Readersecret |
| 16 | PostgreSQL-Anbindung funktioniert. | Echte AsyncEngine über Psycopg |
| 17 | Richtige Datenbankidentität verwendet. | SELECT current_user == api_reader |
| 18 | Keine Superuser-Rechte. | Rollenflags/DDL/SET ROLE negativ |
| 19 | Connection Pooling funktioniert. | Parallele Sessions, Pool Pre-Ping |
| 20 | Verbindungslimits wirksam. | Pool erschöpft: kurzer Timeout und Erholung |
| 21 | Transaktionen funktionieren. | Echter Commit in isolierter DB |
| 22 | Rollback funktioniert. | Exception/Cancellation/Readscope ohne Commit |
| 23 | Parallele Sessions funktionieren. | 12 konkurrierende unabhängige Sessions |
| 24 | Einheitliche JSON-Logs. | JSON-Logformatter und Container-JSONprüfung |
| 25 | UTC-Zeitstempel. | UTC-Test mit ISO-Zeit |
| 26 | Request-IDs funktionieren. | Parallelität, Nginx-Hex, ungültige Werte |
| 27 | Korrelations-IDs funktionieren. | ContextVars, Headerweitergabe, Tokenreset |
| 28 | Einheitliche Fehlerantworten. | Original-Problem-Schema mit 9 Fehlerstatus validiert |
| 29 | Keine internen Stacktraces in produktiven Antworten. | Geheimnisfreie 422/500-Tests |
| 30 | Liveness funktioniert. | Echte ASGI-/Container-Liveness |
| 31 | Readiness funktioniert. | Echte SELECT-1-Readiness |
| 32 | PostgreSQL-Ausfall wird erkannt. | PostgreSQL-Stop/Start im eigenen Testprojekt |
| 33 | Liveness und Readiness korrekt getrennt. | DB-Ausfall: Liveness 200, Readiness 503 |
| 34 | HTTP-Client funktioniert. | Echter Loopback-HTTP-Server |
| 35 | HTTP-Timeouts funktionieren. | ReadTimeout und begrenzter Client-Pool |
| 36 | TLS-Verifikation aktiv. | Ungültige CA abgelehnt, explizite CA akzeptiert |
| 37 | Worker-Lebenszyklus vorbereitet. | run_worker, Stop-Event und Signalunterstützung |
| 38 | Worker-Ressourcen werden kontrolliert freigegeben. | Stop, Cancellation, Wiederholung, Teilstartfehler |
| 39 | `cve-api`-Dockerimage reproduzierbar. | Hash-Wheels, gesperrter Buildbackend, Netzwerk-none-Build |
| 40 | `cve-api`-Container startet. | Realer API-Container gesund |
| 41 | Docker-Netzwerke korrekt. | Nur cve_internal/cve_data |
| 42 | Keine unnötigen öffentlichen Ports. | Keine PortBindings am API-Container |
| 43 | Kein Docker-Socket. | Genau ein privater readonly-Mount, keine Engine API |
| 44 | Keine unnötigen Containerprivilegien. | Nicht-Root, CapDrop ALL, readonly, Limits |
| 45 | Nginx kann intern mit `cve-api` kommunizieren. | wget aus echtem Nginx zu cve-api per Service-DNS |
| 46 | Administrative APIs noch nicht aktiv. | Direkt 404, bisheriger Ingress bleibt gesperrt |
| 47 | Inventar-Upload-APIs noch nicht aktiv. | Keine Uploadrouter; geschlossene Pfade getestet |
| 48 | Keine unerlaubten Fachfunktionen implementiert. | AST-Importgrenzen, kein Worker/Fachcode gestartet |
| 49 | Unit-Tests erfolgreich. | 270 Standardtests, darunter 81 neue Servicetests |
| 50 | Integrationstests erfolgreich. | 10 neue Service-, 40 Ingress-, 189 DB-, 77 Egress-, 36 Mailtests |
| 51 | Sicherheitstests erfolgreich. | Host/Header/TLS/Secret/Rechte-Negativtests |
| 52 | Dokumentation vollständig. | Architektur, Deployment, Sicherheit, Betrieb, Testmatrix |
| 53 | Übergabe an Phase 7 vorbereitet. | phase-06-handover.md |
| 54 | Keine unzulässigen Architekturänderungen. | ADR-0024, Originalverträge/Schemas/Postfix unverändert |

## Sicherheitsinvarianten

| ID | Regel | Nachweis |
|---|---|---|
| PY-01 | Python 3.12 als gemeinsame Basis | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-02 | FastAPI für HTTP-API-Dienste | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-03 | PostgreSQL bleibt das einzige Datenbanksystem | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-04 | Kein Redis | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-05 | Kein zusätzlicher Message Broker | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-06 | Keine zusätzliche Workflow-Engine | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-07 | Gemeinsame Bibliothek enthält keine fachliche CVE-Logik | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-08 | Keine unkontrollierten globalen Datenbankverbindungen | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-09 | Ressourcen werden kontrolliert initialisiert | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-10 | Ressourcen werden beim Shutdown freigegeben | Paket-/Architektur-/Importtests und Ressourcenlebenszyklus |
| PY-11 | Konfiguration wird validiert | Settings-/Secret-/Grant-/Transaktionstests |
| PY-12 | Fehlende Secrets führen nicht zu unsicheren Fallbacks | Settings-/Secret-/Grant-/Transaktionstests |
| PY-13 | Keine Klartext-Secrets im Repository | Settings-/Secret-/Grant-/Transaktionstests |
| PY-14 | Keine Secrets in Logs | Settings-/Secret-/Grant-/Transaktionstests |
| PY-15 | Keine Superuser-Rechte für Anwendungsdienste | Settings-/Secret-/Grant-/Transaktionstests |
| PY-16 | Dienstbezogene Datenbankrechte bleiben erhalten | Settings-/Secret-/Grant-/Transaktionstests |
| PY-17 | Keine Inventar-basierten Gruppenänderungen | Settings-/Secret-/Grant-/Transaktionstests |
| PY-18 | Keine automatische Gruppierung durch Microservice-Grundfunktionen | Settings-/Secret-/Grant-/Transaktionstests |
| PY-19 | Datenbanktransaktionen besitzen kontrollierten Rollback | Settings-/Secret-/Grant-/Transaktionstests |
| PY-20 | Keine gemeinsam verwendeten AsyncSessions über parallele Tasks | Settings-/Secret-/Grant-/Transaktionstests |
| PY-21 | Connection Pools sind begrenzt | Settings-/Secret-/Grant-/Transaktionstests |
| PY-22 | Fehlerantworten geben keine internen Geheimnisse preis | HTTP-/Log-/Health-Negativtests |
| PY-23 | Request-IDs werden validiert | HTTP-/Log-/Health-Negativtests |
| PY-24 | Unvertrauenswürdige Proxy-Header begründen keine Identität | HTTP-/Log-/Health-Negativtests |
| PY-25 | Keine unkontrollierten offenen CORS-Richtlinien | HTTP-/Log-/Health-Negativtests |
| PY-26 | Liveness führt keine fachlichen Schreiboperationen aus | HTTP-/Log-/Health-Negativtests |
| PY-27 | Readiness führt keine fachlichen Schreiboperationen aus | HTTP-/Log-/Health-Negativtests |
| PY-28 | Health-Endpunkte geben keine Secrets preis | HTTP-/Log-/Health-Negativtests |
| PY-29 | Keine unnötigen öffentlichen Service-Ports | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-30 | Kein Docker-Socket | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-31 | Keine unnötigen privilegierten Container | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-32 | Keine allgemeine direkte Internetverbindung | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-33 | HTTPS-Verifikation bleibt aktiv | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-34 | Keine vorzeitig aktiven administrativen APIs | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-35 | Keine vorzeitig aktiven Inventar-Upload-APIs | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-36 | Keine automatische fachliche Jobverarbeitung in Phase 6 | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-37 | Kein vorzeitig implementiertes Dashboard | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-38 | Kein vorzeitig implementierter Service Status Monitor | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-39 | Sicherheitsrelevante Konfigurationen werden negativ getestet | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |
| PY-40 | Fachservices werden erst nach erfolgreicher Integration aktiviert | Echter gehärteter Container, HTTPX/TLS und geschlossene Fachoberfläche |

## Reproduzierbarkeit und Grenzen

Die vollständigen Prüfprotokolle und JUnit-Dateien liegen lokal unter
`.runtime/test-reports/phase-06-*`; [Testmatrix](../testing/phase-06-test-matrix.md).
Eine frische virtuelle Umgebung installierte ausschließlich lokale, hashgesperrte
Runtime-Wheels plus beide Anwendungspakete, ohne Netzwerk und ohne laufende DB.
CI ist erweitert; ein entfernter CI-Lauf oder eine Produktionsfreigabe wird nicht behauptet.

Produktion benötigt externe PKI/private Readerdateien und passende Nicht-Root-UID.
Die API startet ohne automatische Migration oder Rechteerweiterung. Temporäre DB-Ausfälle
führen zu Readiness 503 und lassen Liveness aktiv. Die Nginx-DNS-Kommunikation ist intern
geprüft; öffentliche Fach-/Healthweiterleitungen sind weiterhin nicht aktiviert.
Worker, Jobs/Outbox, Authentifizierung und Dashboard bleiben den Folgephasen vorbehalten.
