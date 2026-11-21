# Entwicklungsumgebung

## Voraussetzungen und Checkout

Linux, Git, GNU Make sowie Python **3.12.x** mit `venv` und `ensurepip` sind erforderlich.
Systempakete müssen gegebenenfalls durch die Systemverwaltung bereitgestellt werden;
das Setup führt kein `sudo` aus. Docker und das Compose-Plugin sind erst ab Phase 2 nötig.
Nach Bereitstellung einer Remote-URL: `git clone <repository-url> cve-monitoring` und
`cd cve-monitoring`. Der aktuelle lokale Projektordner wurde mit Git initialisiert;
eine Remote-URL und ein veröffentlichter Checkout existieren noch nicht.

```bash
make setup
source .venv/bin/activate
make check
```

`PYTHON=/pfad/zu/python3.12 make setup` wählt einen bestimmten Interpreter.
Das Skript ermittelt die Projektwurzel, prüft exakt die Minor-Version 3.12, erstellt eine
fehlende `.venv`, installiert die gesperrten Pakete mit `--require-hashes` und führt `pip check` aus.
Eine vorhandene `.venv` wird geprüft und weiterverwendet. Eine ungültige Umgebung führt zum
Abbruch; sie wird nicht gelöscht. Aktivierung ist für Make-Befehle nicht notwendig.
Zusätzliche bereits installierte Pakete werden beim wiederholten Setup nicht entfernt;
für eine exakt frische Umgebung einen neuen Checkout verwenden.

## Befehle

| Befehl | Zweck |
|---|---|
| `make help` | Befehlsübersicht |
| `make setup` | Lokale Entwicklungsumgebung installieren |
| `make lint` | Ruff-Prüfung |
| `make format` | Python formatieren |
| `make format-check` | Formatierung kontrollieren |
| `make typecheck` | Strikte Mypy-Prüfung |
| `make test` | Pytest ohne produktive Dienste |
| `make validate` | Pflichtstruktur, YAML/JSON, Inventarbeispiele, OpenAPI und Architekturverträge |
| `make security` | Secret-Prüfung mit unveränderter Baseline |
| `make check` | Alle verpflichtenden Prüfungen |

Optionale Coverage: `.venv/bin/python -m pytest --cov --cov-report=term-missing`.
Compose-Validierung wird erst mit echten Compose-Dateien ergänzt und ist derzeit nicht ausgeführt.
JSON-Schemas werden an `*.schema.json` oder `$schema` erkannt und auf gültige Definition geprüft.
Zusätzlich legt contracts/phase-00-manifest.json die versionierten Inventarbeispiele und ihre
positiven/negativen Erwartungen fest. UUID- und RFC3339-Prüfung ist aktiviert; negative Beispiele
müssen aus dem dokumentierten Grund scheitern. Neue Beispiele benötigen eine explizite Erwartung.
OpenAPI 3.1 wird mit openapi-spec-validator semantisch geprüft, inklusive lokaler $ref-Dateien.
Remote-/Pfadflucht-Referenzen werden vor Aufruf des Resolvers abgelehnt. Zusätzliche Prüfungen
sichern die UND-Verknüpfung der Authentifizierungsverfahren, Admin-/Statusgrenzen sowie
Komponenten-/Netz-/Gruppenschreibrechte ab. Lokale Markdown-Dateiverweise werden geprüft.
Doppelte JSON-Schlüssel und nicht standardkonforme Zahlenwerte sind verboten.
Vertragsprüfung allein: .venv/bin/python scripts/validate_contracts.py.
Git liefert versionierte sowie neue, nicht ignorierte Dateien. Bereits versionierte, später
ignorierte Dateien bleiben in den Prüfungen. Symlinks sind manuell zu prüfen und führen zum Fehler.

## Explizite Entwicklungsumgebung

Die Standardvorlage `.env.example` verwendet `APP_ENV=production`. Für lokale
Entwicklung ist die getrennte Vorlage
[development.env](../../configuration/examples/development.env) vorgesehen:

```bash
# Nur wenn noch keine eigene .env vorhanden ist:
cp configuration/examples/development.env .env
chmod 600 .env
./cve_mon config
./cve_mon start
```

Sie setzt `APP_ENV=development`, Projekt `cve-monitoring-dev`, Loopback und
Ports 8080/8443 sowie lokale Laufzeit-/Zertifikatspfade. MailHog und Datenreset
bleiben auf diesen Modus begrenzt. Bestehende Instanzen werden durch eine Änderung
der Vorlagen nicht umgestellt. Das Python-Setup überschreibt keine `.env`.

`make check` verwendet ohne explizites `CVE_ENV_FILE` die Entwicklungsvorlage.
CI wählt diese ebenfalls ausdrücklich. Für einzelne Operatorbefehle kann sie mit
`CVE_ENV_FILE=configuration/examples/development.env` gewählt werden.
Die vollständige Variablenliste steht unter
[Umgebungen](../deployment/environments.md).

## Abhängigkeiten aktualisieren

Direkte Werkzeuge in `requirements/dev.in` exakt pinnen. Unter Linux/Python 3.12:

```bash
.venv/bin/pip-compile --generate-hashes --allow-unsafe --no-emit-index-url \
  --no-emit-trusted-host --output-file requirements/dev.txt requirements/dev.in
make setup
make check
```

Eine gezielte transitive Aktualisierung erfolgt mit `--upgrade-package <name>`;
`--upgrade` nur für eine bewusst geprüfte Gesamtaktualisierung. Lock-Diff, Versionen und Hashes
prüfen und in einem frischen Checkout installieren. pip selbst ist im Lock enthalten;
das mit Python gelieferte ensurepip wird nur für die erstmalige Installation benötigt.
Die reproduzierbare Laufzeitbasis ist Linux/Python 3.12; andere Plattformen separat prüfen.

Grundlage des Hash-Verfahrens: [offizielle pip-tools-Dokumentation](https://pip-tools.pypa.io/en/stable/reference/configuration/).

## Sicherheit und Fehlerbehandlung

`make security` verwendet `detect-secrets-hook` auf allen ausgewählten Dateien, einschließlich
neuer Dateien. `--no-verify` verhindert Netzwerkabfragen zur Token-Verifikation. Ein Fund erzeugt Fehlerstatus; die Baseline wird niemals automatisch erweitert.
Die initiale `configuration/quality/secrets.baseline` enthält keine akzeptierten Funde. Eine `.gitignore` schützt
nicht vor schon versionierten Geheimnissen. Lokale Secrets, Schlüssel, Inventare und Laufzeitdaten
bleiben außerhalb der Versionierung. Erkennung ist heuristisch und ersetzt die Codeprüfung nicht.

Bei einem Fund Inhalt entfernen und gegebenenfalls betroffene echte Zugangsdaten widerrufen.
Ein False Positive wird einzeln geprüft und mit Begründung im Review dokumentiert.
Nur nach dieser Prüfung darf ein konkreter Baseline-Eintrag als `is_verified: false` aufgenommen
werden; echte oder ungeprüfte Funde werden vom Wrapper abgelehnt. Keine pauschalen Ausschlüsse
oder automatisch erzeugten akzeptierten Baselines. Inline-Ausnahmen nur einzeln begründet im Review.
Bei einer Baseline-Änderung muss auch der Test angepasst werden, der aktuell ihre Leere fordert.
Siehe [offizielle detect-secrets-Dokumentation](https://github.com/Yelp/detect-secrets).

Fehlender Interpreter: Python 3.12 bereitstellen oder `PYTHON` setzen. Ungültige `.venv`:
Inhalt sichern und manuell prüfen. Installation oder Hashprüfung fehlgeschlagen: Netzwerk,
Paketindex und Lock prüfen; niemals Hashprüfung deaktivieren. Ein Qualitätsfehler wird mit
Datei/Ursache ausgegeben; beheben und betroffenen Befehl erneut ausführen.

## CI

`.github/workflows/quality.yml` führt auf Push und Pull Request `make setup` und `make check`
unter Python 3.12 aus. Actions sind auf gegen die offiziellen Repositories geprüfte Commit-SHAs
festgelegt. Der Workflow benötigt nur lesenden Repositoryzugriff und keine Produktiv-Secrets.
Ein gehosteter Lauf ist erst nach Veröffentlichung auf GitHub möglich.


## Phase 2

Die [Infrastruktur-Anleitung](../deployment/docker-compose.md) ergänzt Docker, OpenSSL und
[Umgebungsvariablen](../deployment/environments.md). make check prüft zusätzlich beide
Compose-Modelle; make infra-test führt tatsächliche Docker-/TLS-/Netzwerktests aus.
Docker-Tests sind im Standard-Pytest-Lauf bewusst nicht ausgewählt; ausdrücklich angefordert
schlagen sie ohne Daemon fehl und gelten nicht als bestanden. setup selbst benötigt weiter kein sudo.

## Datenbank ab Phase 3

Zusätzliche gesperrte Werkzeuge: Alembic, SQLAlchemy und Psycopg mit Binarywheel.
`make check` bleibt daemonfrei; `make db-test` fordert eine echte isolierte PostgreSQL-Instanz
inklusive Restore an. `make db-security-test` prüft echte technische Logins und Rechte.
Bei erforderlichem passwortlosen sudo `CVE_DOCKER_SUDO=1` voranstellen.
[Start, Secrets und Migrationen](../deployment/postgresql.md),
[Backup/Restore](../operations/postgresql-backup-restore.md), [Abnahme](phase-03-acceptance.md).

## Envoy ab Phase 4

`make envoy-test` fordert echte eigene HTTP-/TLS-/DNS-/SMTP-Container und Linux-nsenter/nft an.
Keine zusätzlichen Pythonbibliotheken; bei nötigem Dockerzugang `CVE_DOCKER_SUDO=1`.
Der Importlib-Modus verhindert Modulnamenskollisionen zwischen den getrennten Testsuiten.
[Betrieb](../deployment/envoy.md), [Abnahme](phase-04-acceptance.md).

Ab Phase 6 installiert `make setup` auch die eigenständigen lokalen Pakete cve-common
und cve-api ohne zusätzliche Auflösung der bereits gesperrten Runtime-Abhängigkeiten.
`make services-test` benötigt keine Docker-Dienste; `make services-integration`
verwendet ein vollständig eigenes PostgreSQL/API/Nginx-Projekt.
[Konfiguration/Betrieb](../deployment/python-services.md).

## Inventarannahme ab Phase 11

`CLIENT_CRL_FILE` bezeichnet die signierte, aktuelle Sperrliste der Client-CA. Ohne
expliziten Wert wird der Pfad aus `CLIENT_CA_FILE` mit Endung `.crl` abgeleitet.
Die lokale Test-PKI darf sie bei fehlender Datei erzeugen; vorhandene Dateien werden
nicht überschrieben. Produktiv ist die aktuelle Sperrliste bereitzustellen.
`INVENTORY_MAX_BYTES` begrenzt Originaldateien auf höchstens 10485760 Bytes (10 MiB),
zulässig sind 1024 bis 10485760 Bytes. Multipart erhält höchstens 1 MiB Zusatzrahmen.
Die private Gateway-Capability, der Token-HMAC-Schlüssel und das separate
api_ingest-Kennwort werden über `make api-prepare` als geschützte Dateien bereitgestellt.
Sie gehören nicht in `.env`. [Inventarbetrieb](../operations/inventory-upload.md).

## Phase 15

`make cve-importer-check` prüft den neuen Quellenimporter; vollständige isolierte
Docker-/PostgreSQL-/Envoy-Prüfungen: `make cve-importer-integration`.
Konfiguration: `CVE_IMPORTER_WORKER_CONCURRENCY` (1–2), `CVE_IMPORTER_WORKER_LEASE_SECONDS`,
`CVE_IMPORTER_WORKER_HEARTBEAT_SECONDS`, `CVE_IMPORTER_WORKER_POLL_SECONDS` und
`CVE_IMPORTER_WORKER_SHUTDOWN_SECONDS`. Defaults 1/15/3/0.5/5; Heartbeat höchstens Lease/3.
Private Quellkonfiguration und explizite OSV-Auswahl siehe [Betrieb](../operations/cve-importer.md).

## Phase 16

`make cve-enricher-check` und `make cve-enricher-integration` prüfen Quellenregeln, CVSS,
EPSS, PostgreSQL, Egress und Wiederanlauf. Workergrenzen: `CVE_ENRICHER_WORKER_CONCURRENCY`,
`CVE_ENRICHER_WORKER_LEASE_SECONDS`, `CVE_ENRICHER_WORKER_HEARTBEAT_SECONDS`,
`CVE_ENRICHER_WORKER_POLL_SECONDS`, `CVE_ENRICHER_WORKER_SHUTDOWN_SECONDS`.
Defaults 1/15/3/0.5/5, höchstens zwei Worker und Heartbeat höchstens Lease/3.

## Phase 17: Offline-Matcher

`make matching-check` prüft Fachregeln und native Versionsoracles. Installiere für das RPM-Oracle `librpm9` (auf Ubuntu ggf. t64); der Runtimecontainer benötigt dieses Paket nicht. `CVE_DOCKER_SUDO=1 make matching-integration` verwendet isolierte Projekte. `matching-build` und `matching-up` bauen/starten ausschließlich den vorgesehenen Worker. Ein Backfill benötigt einen expliziten `scripts.cve_matcher.manage enqueue --kind reconcile`-Auftrag. Konfiguration: CVE_MATCHER_WORKER_CONCURRENCY (1..4), LEASE_SECONDS, HEARTBEAT_SECONDS, POLL_SECONDS, SHUTDOWN_SECONDS mit demselben Präfix; Grenzen wie bestehende Worker, Heartbeat ≤ Lease/3. Keine externen Matcherhosts oder Proxyfreigaben.

| Matcher-Variable | Standard | Grenze |
|---|---|---|
| CVE_MATCHER_WORKER_CONCURRENCY | 1 | 1..4 |
| CVE_MATCHER_WORKER_LEASE_SECONDS | 15 | 0.2..300 |
| CVE_MATCHER_WORKER_HEARTBEAT_SECONDS | 3 | 0.05..100, ≤ Lease/3 |
| CVE_MATCHER_WORKER_POLL_SECONDS | 0.5 | 0.05..10 |
| CVE_MATCHER_WORKER_SHUTDOWN_SECONDS | 5 | 0.1..5 |

## Phase 18: Finding Management

make findings-check und CVE_DOCKER_SUDO=1 make findings-integration prüfen die gesamte Domain. Der Worker braucht keine externen Sicherheitsdaten oder SMTP. Die API und das Finding-Paket werden aus denselben Quellen gebaut.

| Variable | Standard | Grenze |
|---|---|---|
| CVE_FINDINGS_WORKER_CONCURRENCY | 1 | 1..4, Poolheadroom |
| CVE_FINDINGS_WORKER_LEASE_SECONDS | 15 | 0.2..300 |
| CVE_FINDINGS_WORKER_HEARTBEAT_SECONDS | 3 | 0.05..100, ≤ Lease/3 |
| CVE_FINDINGS_WORKER_POLL_SECONDS | 0.5 | 0.05..10 |
| CVE_FINDINGS_WORKER_SHUTDOWN_SECONDS | 5 | 0.1..5 |
| CVE_FINDINGS_WORKER_MAINTENANCE_SECONDS | 60 | 10..3600 |


## Phase 19: Benachrichtigungen und n8n

CVE_DOCKER_SUDO=1 make notifications-build und make notifications-up starten die beiden
privaten Dienste nach Migration auf 00027. n8n arbeitet ohne Redis im Regular Mode,
mit eigener PostgreSQL-Datenbank, TLS, verschlüsselten Credentials und persistentem Key.
Normale Regeln und Postfix-Freigaben bleiben bis zur ausdrücklichen Konfiguration geschlossen.

| Variable | Standard | Grenze |
|---|---|---|
| CVE_NOTIFICATION_WORKER_CONCURRENCY | 1 | 1..4, Poolheadroom |
| CVE_NOTIFICATION_WORKER_LEASE_SECONDS | 15 | 0.2..300 |
| CVE_NOTIFICATION_WORKER_HEARTBEAT_SECONDS | 3 | 0.05..100, ≤ Lease/3 |
| CVE_NOTIFICATION_WORKER_POLL_SECONDS | 0.5 | 0.05..10 |
| CVE_NOTIFICATION_WORKER_SHUTDOWN_SECONDS | 5 | 0.1..5 |
| CVE_NOTIFICATION_WORKER_MAINTENANCE_SECONDS | 60 | 10..3600 |

Die Aufbereitung läuft standardmäßig mit `CVE_ENRICHER_PROCESSES=2` und
`CVE_ENRICHER_WORKER_CONCURRENCY=4` je Prozess, zusammen bis zu acht parallelen Jobs.
Prozesszahl (1–2), Parallelität (1–4) und Datenbankpools sind begrenzt; je Prozess stehen
acht Verbindungen einschließlich Headroom für Heartbeats bereit. Zum Reduzieren der
Last können beide Variablen abgesenkt werden. Der Quellencontainer bleibt ein einzelner
Container mit vier CPU-Kernen als Obergrenze. PostgreSQL hat vier CPU-Kerne, 2 GiB
Speicherlimit, 512 MiB Shared Buffers und maximal 96 Verbindungen. Das Herstellerimage
bleibt unverändert; diese Werte stammen ausschließlich aus Compose beziehungsweise
`infrastructure/postgres/postgresql.conf`.

`CVE_MATCHER_PROCESSES` startet standardmäßig zwei Matcher-Prozesse (erlaubt: 1–2)
im gemeinsamen Verarbeitungscontainer. Je Prozess sind höchstens vier Jobs mit
fünf Datenbankverbindungen erlaubt; insgesamt bleibt das Matcher-Poolbudget bei zehn.

Die optionale integrierte SSH-Erfassung arbeitet mit zwei parallelen Jobs.
Zieladressen und Zielnetze sind nicht eingeschränkt. Die Erfassung erfolgt ohne sudo
und verändert keine Zielkonfiguration. Voraussetzungen und Löschverhalten:
[Automatische Servererfassung](../operations/managed-ansible.md).
