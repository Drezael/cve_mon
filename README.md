# CVE Security Monitoring Platform

CVE Monitor erfasst Serverinventare, gleicht Betriebssystem-, Paket- und
Containerinformationen mit CVE-Daten ab und stellt Findings, Prioritäten und
Benachrichtigungen im Dashboard bereit. Inventare können als Datei hochgeladen
oder automatisch über SSH/Ansible erfasst werden. n8n steuert die Hintergrundläufe.

Der normale Stack besteht aus **sieben Containern**: Nginx, PostgreSQL, n8n,
Postfix sowie API, Verarbeitung und Quellen/SSH-Ausführung. Die drei eigenen
Dienste verwenden ein gemeinsames Anwendungsimage; die vier Herstellerimages
bleiben unverändert. Optional ergänzt Certbot die automatische Zertifikatspflege
über Cloudflare DNS-01. MailHog gehört ausschließlich zum Mailtestbetrieb.

**[Ausführliche Bedienungsanleitung](docs/bedienungsanleitung.md)** · Installation,
Dashboard-Bedienung, Inventarisierung, Administration und Betrieb.

## Lizenz

Nichtkommerzielle Nutzung ist unter [PolyForm Noncommercial 1.0.0](LICENSE)
zulässig. **Kommerzielle Nutzung erfordert eine gesonderte Lizenzvereinbarung**
mit den Rechteinhabern. Der Quellcode ist öffentlich einsehbar; die Bedingungen
sind in [Lizenzierung](docs/legal/licensing.md) beschrieben.

## Installation und Start

Erforderlich sind Linux, Docker mit Compose-Plugin und Python **3.12**.
`./cve_mon` richtet seine lokale `.venv` ein und verwendet sie automatisch.

```bash
cp .env.example .env
chmod 600 .env
# Externe Angaben in .env an die eigene Umgebung anpassen.
./cve_mon setup
./cve_mon config
./cve_mon start  # Erstinstallation
./cve_mon health
```

Die Standardvorlage verwendet **`APP_ENV=production`**, Projekt
`cve-monitoring-prod` und die Ports 80/443. Vor dem Start eigene Domain, Datenpfade
und Zertifikate beziehungsweise Cloudflare DNS-01 konfigurieren.
Für ausdrücklich lokale Entwicklung stattdessen
[development.env](configuration/examples/development.env) als `.env` verwenden.
Bestehende `.env`-Dateien werden nicht automatisch umgestellt.

Bei jedem Start des n8n-Containers werden die Workflow-Definitionen aus dem
Repository automatisch importiert und veröffentlicht, bevor n8n seine Zeitpläne
und Webhooks startet. Dies gilt auch für Docker-Neustarts. Ein separates Argument
ist nicht erforderlich; bestehende Workflow-IDs werden aktualisiert.
Gespeicherte Importzeitpläne und Pause-Einstellungen bleiben erhalten. Falls Docker ausschließlich über eingerichtetes passwortloses sudo
zugänglich ist, `./cve_mon --sudo …` verwenden.

```bash
./cve_mon status
./cve_mon logs -f api
./cve_mon stop   # Dienste und Hostcontroller stoppen, Daten behalten
./cve_mon down   # zusätzlich Container und Netzwerke entfernen, Daten behalten
```

Den ersten Administrator nach der [Anleitung](docs/operations/initial-administrator.md)
anlegen. Neue reguläre Konten erhalten die Rolle `user`; Administratoren besitzen
zusätzlich diese Rolle. Berechtigungen für Server und Gruppen werden im Dashboard
verwaltet. Eigene Dashboards lassen sich über YAML erstellen und importieren:
[Anleitung](docs/dashboard/custom-dashboards.md),
[Vorlage](configuration/dashboards/security-overview.yaml).

## Konfiguration, Daten und Zertifikate

Die `.env` enthält ausschließlich externe Angaben: Betriebsmodus und Projektname,
Hostverzeichnisse, Dashboard-Domain und Bind-Adresse/Ports, Zertifikatsordner sowie
externe SMTP-Anbindung. Interne Dienstadressen, Ports, Datenbankrollen und
Workerbudgets sind im Repository und in Compose festgelegt.

| Einstellung | Bedeutung |
|---|---|
| `APP_ENV` | Standard `production`; `development` nur ausdrücklich für lokale Tests |
| `COMPOSE_PROJECT_NAME` | Getrennte Daten und Ressourcen je Installation |
| `MOUNT_BASE` | Basis für veränderliche Containerdaten, beispielsweise `/mnt` |
| `SECRETS_BASE` | Private Schlüssel und automatisch verwaltete Dienstkonfigurationen, beispielsweise `/mnt/secrets` |
| `DASHBOARD_DOMAIN` | Öffentlicher DNS-Name des Dashboards |
| `INGRESS_BIND_IP`, `INGRESS_HTTP_PORT`, `INGRESS_HTTPS_PORT` | Veröffentlichte Dashboard-Adresse und Ports |
| `TLS_DIR` | Extern gepflegter Zertifikatsordner, wenn die automatische Ausstellung deaktiviert ist |
| `LETSENCRYPT_ENABLED`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_AGREE_TOS` | Optionalen Certbot-Dienst aktivieren, Kontakt und Zustimmung |
| `CLOUDFLARE_API_TOKEN` | Eingeschränkter DNS-Token für die Dashboard-Zone |
| `SMTP_*` | Externer Mailserver, Absender und optionale Zugangsdaten |

Persistente Containerdaten verwenden Bind-Mounts mit eigenen Dienst-/Projektordnern.
Statische, read-only eingebundene Konfigurationen und Skripte bleiben im Repository.
Vor Änderungen an den Basisverzeichnissen den Stack stoppen; der nächste Start
übernimmt bestehende Daten und lässt die ursprünglichen Bestände als Rückfallkopie
zurück. Interne Secrets werden automatisch eingerichtet und wiederverwendet.

Für Serverbetrieb die [Produktionsvorlage](configuration/examples/server.env)
verwenden, insbesondere Domain, Verzeichnisse und veröffentlichte Adresse anpassen:

```dotenv
APP_ENV=production
DASHBOARD_DOMAIN=dashboard.example.org
TLS_DIR=/etc/letsencrypt/live/dashboard.example.org
```

Optional stellt ein Certbot-Container das öffentliche Zertifikat automatisch über
**Cloudflare DNS-01** aus und erneuert es. Dafür `LETSENCRYPT_ENABLED=true`,
Kontaktadresse, Zustimmung und einen eingeschränkten Cloudflare-DNS-Token setzen.
Es gibt keinen HTTP-Challenge-Fallback und keine zusätzlich veröffentlichten Ports.
Ablage und Dienstpfade werden automatisch abgeleitet; `TLS_DIR` wird in diesem
Modus nicht benötigt. Die [Einrichtungsanleitung](docs/deployment/letsencrypt-cloudflare.md)
beschreibt Tokenanlage, Erststart und Testerneuerung.

Bei `LETSENCRYPT_ENABLED=false` stellt ein externes ACME-Werkzeug die Dateien in
`TLS_DIR` bereit. Certbot-Symlinks nach `archive/` werden unterstützt. Der
Hostcontroller prüft Änderungen alle 60 Sekunden und lädt Nginx nach erfolgreicher
Prüfung neu. Interne Dienstzertifikate verwaltet die Anwendung separat.
Im Entwicklungsmodus sind lokale Testzertifikate möglich.

```bash
./cve_mon --env-file /etc/cve-monitor/server.env config
./cve_mon --env-file /etc/cve-monitor/server.env start
./cve_mon --env-file /etc/cve-monitor/server.env health
```

**Von außen ist ausschließlich das Dashboard erreichbar**, einschließlich Anmeldung
und benötigter Dashboard-API. n8n, Datenbank, Mailrelay und die übrigen Dienste
besitzen keine veröffentlichten Hostports. Ihre technische Konfiguration erfolgt
im Repository beziehungsweise in Compose. Es gibt keine separaten öffentlichen
n8n-, API- oder Inventar-Domains.

Details: [Umgebungen](docs/deployment/environments.md),
[Controllerbetrieb](docs/deployment/start-controller.md),
[Architekturvorgaben](docs/architecture/decisions/ADR-0038-external-configuration.md).

## Automatische Ansible-Inventarisierung

Die optionale SSH-Verbindung wird je Server in der Serververwaltung eingerichtet.
Zuerst muss jeder Benutzer unter **Einstellungen → Mein Ansible-Vault** ein eigenes
Vault-Passwort hinterlegen. SSH-Passwörter, private Schlüssel und Passphrases werden
im persönlichen Vault verschlüsselt gespeichert; es gibt keine Anzeige oder
Downloadfunktion für gespeicherte Geheimnisse. Bestehende Profile müssen nach der
Vault-Umstellung mit ihren Zugangsdaten erneut gespeichert werden.

Anschließend Zieladresse, SSH-Port, Benutzer und Schlüssel oder Passwort hinterlegen, den
SSH-Hostkey mit dem Zielhost vergleichen und bestätigen, anschließend die
Verbindung testen. Danach sind manuelle und regelmäßige Erfassungen möglich.
**Alle Zielnetze und Zieladressen sind zulässig**; eine Netz-Allowlist in der `.env`
entfällt. Die Firewall des Executors lässt neben der internen Datenbank nur die
konkret hinterlegten aktiven SSH-Ziele zu.

Auf jedem Zielhost sollte ein **eigener Benutzer mit beschränkten Rechten**, etwa
`cve-inventory`, angelegt werden. SSH-Schlüssel bevorzugen, keine sudo-Rechte und
keinen Root-Login vergeben. Nur die für Inventare benötigten Dateien, Paketdaten
und gegebenenfalls explizit ausgewählte Anwendungsmounts lesbar machen.

Die integrierte Erfassung arbeitet **ausschließlich lesend an den überwachten
Beständen**: Sie installiert keine Pakete oder Werkzeuge, ändert keine Dienste,
Konfigurationen oder Container und führt keine Befehle in überwachten Containern
aus. sudo-Ausführung und Root-Anmeldung sind ausgeschlossen. Bestehende Profile
mit sudo müssen auf den beschränkten Benutzer ohne sudo umgestellt werden.
Für Ansible-Ausführung und SBOM-Auswertung können private temporäre Arbeitsdateien
auf dem Zielhost entstehen; diese werden nach dem Lauf entfernt. Es werden keine
dauerhaften Collector-Dateien, Host-IDs oder SBOM-Caches neu angelegt.

Folgende Voraussetzungen richtet ein Administrator **vorab** auf dem Zielhost ein:

| Zweck | Voraussetzungen auf dem Zielhost |
|---|---|
| SSH und Systeminventar | SSH-Server, Python 3 und lesbare System-/Paketinformationen |
| Paketdaten je Distribution | gegebenenfalls `python3-apt` für Debian/Ubuntu oder `python3-rpm` für RPM-Systeme |
| Docker-Metadaten | Docker-CLI und Zugriff auf einen beschränkten Docker-Leseendpunkt |
| Software in Docker-Images und Containerdateisystemen | Syft unter `/usr/local/bin/syft`; Referenzversion und SHA256 stehen in [syft.lock.json](scripts/container_inventory/syft.lock.json) |
| Ressourcenlimits für die Analyse | `/usr/bin/prlimit`, üblicherweise aus `util-linux` |

**Die normale `docker`-Gruppe ist kein Lesezugang**: Zugriff auf den unbeschränkten
Docker-Socket gewährt weitreichende Verwaltungsrechte. Deshalb einen durch einen
Administrator eingerichteten API-Proxy beziehungsweise eine Autorisierung verwenden,
die ausschließlich die benötigten Leseoperationen erlaubt. Der Collector verwendet
fest `unix:///run/cve-monitoring/docker-readonly.sock`; es gibt keinen Rückfall auf
den normalen Docker-Socket. Details und benötigte API-Operationen stehen in der
[Ansible-Betriebsanleitung](docs/operations/managed-ansible.md).
[Docker erläutert die Rechte des Daemonzugriffs](https://docs.docker.com/engine/security/).

Syft liest lokal vorhandene Images; es werden keine Images nachgeladen. Für
Container mit Änderungen am Dateisystem kann ein lesender Export analysiert werden.
Anwendungsmounts werden nur nach expliziter Auswahl und mit vorhandenen Leserechten
einbezogen. Fehlende Werkzeuge oder Rechte führen zu fehlenden beziehungsweise
unvollständigen Inventardaten, nicht zu einer automatischen Rechteerweiterung.
Die CVE-Bewertung erfolgt anschließend im Monitor.

[Einrichtung, Betrieb und dauerhaftes Löschen](docs/operations/managed-ansible.md).
Alle verwendeten Playbooks liegen in diesem Repository:
[Erfassung](services/automation/src/cve_automation/playbooks/collect.yml) und
[Verbindungstest](services/automation/src/cve_automation/playbooks/connection-test.yml).
Dieselben Dateien werden in das Anwendungsimage gepackt und vom SSH-Executor geladen.
Ein externes Ansible-Repository oder dessen Launcher ist nicht erforderlich.
Die [Ansible-Anleitung](integrations/ansible/README.md) beschreibt auch die lokale
Erfassung einer JSON-Datei für den Dashboard-Upload und die Prüfziele.

## Mailtests

MailHog wird bei normalem Start nicht mitgestartet. Nur im Entwicklungsmodus:

```bash
./cve_mon mail-test start
./cve_mon mail-test status
./cve_mon mail-test stop
```

Die Testoberfläche liegt auf `http://127.0.0.1:8025`. Für einen Test im Dashboard
`mailhog.cve.test:1025` als SMTP-Ziel wählen. SMTP-Einstellungen werden nicht
automatisch umgestellt. `stop` entfernt den Testcontainer und behält die Testdaten.
Die optionale Compose-Datei ist [mail-test.yml](infrastructure/compose/mail-test.yml).

## Vollständiger Entwicklungsreset

```bash
./cve_mon reset --confirm cve-monitoring-dev
./cve_mon start
```

Der Bestätigungswert muss dem Projektnamen entsprechen. Der Reset stoppt das
Entwicklungsprojekt und löscht dessen Daten einschließlich Konten, Einstellungen,
Inventaren und n8n-Daten. `.env`, bereitgestellte Eingangszertifikate und Backups
bleiben erhalten. Für Produktionsprojekte ist der Befehl gesperrt.

## Entwicklung und Dokumentation

`make help` zeigt die Entwicklungsziele; `make check` führt die vorgesehenen lokalen
Prüfungen aus. Werkzeuge werden lokal installiert. Historische Phasenbeschreibungen
in `docs/development/` dokumentieren frühere Entwicklungsstände. Die alten
Entwicklungs- und Umsetzungspläne bleiben lokal und sind von GitHub ausgeschlossen.

- [GitHub-Übernahme](docs/development/github.md)
- [Beiträge](.github/CONTRIBUTING.md)
- [Sicherheitsmeldungen](.github/SECURITY.md)
- [Entwicklungsumgebung](docs/development/developer-setup.md)
- [Architektur](docs/architecture/README.md)
- [Betriebshandbuch](docs/operations/platform-handbook.md)
- [Bedienungsanleitung](docs/bedienungsanleitung.md)
- [Cloudflare DNS-01 und automatische Zertifikate](docs/deployment/letsencrypt-cloudflare.md)
- [Eigene Dashboards: alle Widgets und Ressourcenquellen](docs/dashboard/custom-dashboards.md)
- [Backups und Wiederherstellung](docs/operations/postgresql-backup-restore.md)
- [SMTP-Konfiguration](docs/operations/smtp-configuration.md)
- [n8n-Workflows](workflows/n8n/README.md)

| Verzeichnis | Inhalt |
|---|---|
| `services/`, `packages/` | Anwendung, Dashboard und gemeinsame Bibliotheken |
| `infrastructure/`, `compose.yml` | Container, feste Infrastruktur und Laufzeitvorgaben |
| `configuration/`, `examples/` | Konfiguration, Release-Schemas, Vorlagen und Beispielinventare |
| `database/`, `contracts/` | Migrationen und Daten-/API-Verträge |
| `scripts/`, `requirements/` | Controller, Betriebs- und Entwicklungswerkzeuge |
| `integrations/`, `workflows/` | Collector-Anbindung und Orchestrierung |
| `tests/`, `docs/` | Prüfungen und Dokumentation |
