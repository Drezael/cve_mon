> Aktueller Betrieb: Die acht logischen Module laufen als API, Verarbeitung und Datenquellen in drei Containern mit einem gemeinsamen Image. [Betrieb und interne Endpunkte](compact-runtime.md).

# Python-Dienste bereitstellen

Voraussetzungen aus Phase 0–5 sowie Python 3.12. `make setup` installiert gesperrte
Dev-/Runtime-Abhängigkeiten und die beiden lokalen Pakete mit festgelegtem Buildbackend.
Runtime allein: requirements/runtime.txt mit --require-hashes; alle Versionen transitiv
gesperrt. Runtime und Entwicklungswerkzeuge bleiben getrennte Eingabedateien.

```bash
make setup python-check services-test
CVE_DOCKER_SUDO=1 make services-integration
CVE_DOCKER_SUDO=1 make db-up db-provision db-migrate
CVE_DOCKER_SUDO=1 make api-build api-prepare api-up api-smoke-test
CVE_DOCKER_SUDO=1 make api-down
```

DB-Secrets aus Phase 3 müssen vorher bereitstehen (`make db-secrets` für neue lokale
Entwicklung). Keine Passwortresets; Migration/Provisionierung sind ausdrückliche
Operatoraktionen, niemals Teil des API-Starts. sudo nur für bereits autorisierten
passwortlosen Docker-Zugang, keine Host-/fremde Namespace-Veränderung.

Der Build lädt hashgesperrte Wheels, baut cve-common/api mit festgelegtem Backend und
installiert im Docker-Build ohne Netzwerk. Kontext `.runtime/python-image` enthält nur
Dockerfile, Runtime-Lock und Wheels/SHA256-Manifest, keine Secrets oder ganze Repositorykopie.
Offizielles CPython-3.12-/Alpine-3.24-Image per Digest; Image cve-api:0.23.0-phase23.
Der Operator lädt die hashgesperrten Runtime-Wheels gezielt für musllinux (CPython 3.12, amd64). Aktualisierung von
Lock, Paketmetadaten und lokalem Imagetag kontrolliert gemeinsam testen.

API nur in cve_internal/cve_data, interner Port 8000 ohne Hostmapping. Read-only, alle
Capabilities entfernt, no-new-privileges, begrenztes tmpfs/RAM/CPU/PIDs/FDs. Image-
Standardbenutzer 65532; Compose verwendet den vorhandenen nichtprivilegierten NGINX_UID/GID
als Dateibesitzer für private Host-Bindmounts. Keine Berechtigungserweiterung, keine
Abhängigkeit vom Nginx-Prozess. UID muss zu den privaten Betreiberdateien passen.

`api-prepare` kopiert ausschließlich api_reader und öffentliche DB-CA nach
`.runtime/services/<projekt>` (0700; Passwort 0600), nur dieser Pfad wird read-only
an die API gemountet. Für die seit Phase 6 hinzugekommenen API-Funktionen werden weitere eng berechtigte Kontextrollen und Auth-Schlüssel privat bereitgestellt; das aktuelle Compose-Modell und die Sicherheitsdokumentation sind maßgeblich. Migrations-/Superuser-Credentials und SMTP-Secrets werden nicht an die API gemountet. Getrennte Kontextpools sind keine Prozessisolation. Bestehende Dateien bleiben erhalten. Produktion benötigt
extern provisionierte Dateien/PKI; lokale Entwicklungs-PKI wird nicht automatisch freigegeben.
Rotation: private API-Datei abgestimmt mit DB-Credential ersetzen und API neu erstellen;
kein Dockerfile-Secret und kein Passwort in Umgebungsvariablen oder Prozessargumenten.

Uvicorn: ein Prozess, 32 parallele Verbindungen, Backlog 64, Keepalive 5 s,
Graceful Shutdown 10 s, Docker-Grace 15 s; kein Reload, keine universell vertrauten
Proxyheader. Zusätzliche Prozesse erzeugen zusätzliche Pools und müssen gemeinsam
mit PostgreSQL-Verbindungslimits geplant werden.

Nginx erreicht API über Docker-Service-DNS; die Integrationssuite prüft dies aus dem
Nginx-Container. Öffentliche Routen bleiben wie Phase 2 auf 503 gesperrt, keine
Healthweiterleitung nach außen und keine Verwaltungs-/Uploadfreigabe. In dieser Phase
wird bewusst keine öffentliche Reverse-Proxy-Route zur API aktiviert.

## Abgenommene Versionen

Python lokal 3.12.3, im gepinnten Container 3.12.13.

| Paket | Version |
|---|---|
| cve-common | 0.6.0 |
| cve-api | 0.6.0 |
| fastapi | 0.162.0 |
| uvicorn | 0.54.0 |
| pydantic | 2.14.3 |
| pydantic-settings | 2.16.2 |
| SQLAlchemy | 2.1.8 |
| psycopg | 3.3.8 |
| httpx | 0.28.1 |
| greenlet | 3.5.6 |
| starlette | 1.10.0 |

Primärquellen zur verwendeten Architektur: [FastAPI Lifespan](https://fastapi.tiangolo.com/advanced/events/),
[SQLAlchemy AsyncIO](https://docs.sqlalchemy.org/en/21/orm/extensions/asyncio.html),
[HTTPX Proxykonfiguration](https://www.python-httpx.org/advanced/proxies/).

Das gemeinsame Anwendungsimage basiert auf dem unveränderten offiziellen Python-Image. Version und Digest stehen in `infrastructure/images.lock.json` und `services/application/Dockerfile`. Psycopg verwendet das unveränderte `psycopg-binary`-Wheel, sodass weder libpq noch CPython oder Systembibliotheken selbst kompiliert werden müssen. Die Python-Abhängigkeiten sind weiterhin mit Hashes gesperrt. `make setup` installiert die Entwicklungsumgebung; ein lokaler C-Compiler oder PostgreSQL-Entwicklungsheader sind für den Treiber nicht erforderlich.

Siehe [Original-Images und Updates](upstream-images.md). Der frühere Phase-23-Behebungsnachweis beschreibt ausschließlich den historischen Eigenbau.
