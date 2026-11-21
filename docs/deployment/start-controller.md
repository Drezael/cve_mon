# Ein Einstieg für CVE Monitor

`./cve_mon` übernimmt das Bedienkonzept von `factory.sh` und enthält den bisherigen
lokalen Startcontroller direkt. Es startet keine Kette separater Kommandozeilenskripte.
Interne Module für Migrationen, Zertifikate, Netzwerkfreigaben und n8n werden als
Bibliotheken verwendet. Frühere Make-Startziele und `scripts.application.manage`
leiten lediglich auf diesen Controller um.

| Befehl | Verhalten |
|---|---|
| `./cve_mon setup` | Python 3.12 prüfen, `.venv` vorbereiten, hashgesperrte Pakete installieren |
| `./cve_mon config` | Compose validieren; keine Secretwerte ausgeben |
| `./cve_mon --sudo start` | Stack der gewählten Umgebung kontrolliert starten |
| `./cve_mon --sudo build` | Gemeinsames Anwendungsimage und Dashboard bauen |
| `./cve_mon --sudo status` | Alle Container des gewählten Projekts anzeigen |
| `./cve_mon --sudo health` | Acht gesunde Container, Schema und Hostcontroller prüfen |
| `./cve_mon --sudo logs -f api` | Fortlaufende API-Logs, Abbruch mit Strg+C |
| `./cve_mon --sudo logs --tail 50 matcher` | Letzte Logs der gemeinsamen Verarbeitungsgruppe |
| `./cve_mon --sudo stop` | Projekt-Hostcontroller und alle sieben Kerndienste stoppen |
| `./cve_mon --sudo down` | Zusätzlich Projektcontainer und Netzwerke entfernen; Bind-Mount-Daten behalten |
| `./cve_mon --sudo reset --confirm cve-monitoring-dev` | Alle aktiven Daten des bestätigten Entwicklungsprojekts löschen |

Ohne notwendigen sudo-Zugang `--sudo` weglassen. `CVE_DOCKER_SUDO=1` wird weiterhin
unterstützt. sudo wird ausschließlich für Docker verwendet, nicht für Python,
Paketinstallation oder Konfigurationsdateien. Konfiguration kommt aus `.env`,
ersatzweise die Produktivvorlage `.env.example` (`APP_ENV=production`).
Für lokale Tests die getrennte Vorlage `configuration/examples/development.env`
ausdrücklich wählen; bestehende `.env`-Dateien bleiben unverändert. Eine andere Datei wird vor dem Befehl gewählt:

```sh
./cve_mon --env-file /absoluter/pfad/development.env --sudo start
```

Die `.env` wird weder ausgeführt noch automatisch überschrieben. Das Skript findet
sein Repository und seine Python-Umgebung unabhängig vom aktuellen Arbeitsverzeichnis.
Es erwartet für Einrichtung/Start Python 3.12 und ein modernes Compose-Plugin mit
`up --wait` und `config --hash`.

Schlägt ein Werkzeug fehl, zeigt der Controller dessen Exit-Code und bis zu 4000
Zeichen der erfassten Fehlerausgabe. Datenbank-/SMTP-Passwörter, Cloudflare-API-Tokens sowie
Zugangsdaten in URLs werden ausgeblendet. Kommandoargumente und die Standardausgabe
werden nicht als Fehlerdiagnose ausgegeben.

## Start und Wiederanlauf

Das Basisverzeichnis veränderlicher Containerdaten wird zentral in `.env` eingestellt:

```dotenv
MOUNT_BASE=/mnt
```

Nur veränderliche Containerdaten folgen dieser Einstellung. Dienstbezogene Ordner
und der Compose-Projektname trennen die Daten verschiedener Installationen.
Statische Konfigurationen und Hilfsskripte bleiben innerhalb des Repositories.
Zertifikate, private Schlüssel und erzeugte private Dienstkonfigurationen folgen
separat `SECRETS_BASE`, beispielsweise `/mnt/secrets`. `PG_WORK_DIR` folgt
standardmäßig `SECRETS_BASE/database`. Die Vorlage verwendet für beide Basen
kompatibel `./.runtime`; die aktuelle lokale Installation verwendet `/mnt` für
Daten und `/mnt/secrets` für private Dateien.

| Hostpfad relativ zu `MOUNT_BASE` | Containerpfad |
|---|---|
| `storage/<projekt>/postgres-data/` | `/var/lib/postgresql` |
| `storage/<projekt>/postfix-queue/` | `/var/spool/postfix` |
| `storage/<projekt>/mailhog/` (nur Mailtest) | `/home/mailhog` |
| `acme/<projekt>/config/`, `work/`, `logs/` (optional) | Certbot-Konto, Zertifikate, Arbeitsdaten und Protokolle |
| `n8n/<projekt>/data/` | `/home/node/.n8n` |
| `cve-importer/<projekt>/scratch/` | `/work/importer` |
| `cve-enricher/<projekt>/scratch/` | `/work/enricher` |
| `status/<projekt>/postfix/` | `/run/cve-status/postfix` |

Die Statusdaten werden von Postfix geschrieben und zusätzlich read-only in die
API eingebunden. Ihre Datenquelle bleibt deshalb ebenfalls unter `MOUNT_BASE`.
Für öffentliche Zertifikate genügt `TLS_DIR` mit den Let’s-Encrypt-Dateien
`fullchain.pem` und `privkey.pem`. Es gibt keine einzelnen Zertifikatspfad-Optionen.
Mit `LETSENCRYPT_ENABLED=true` stellt der optionale Certbot-Dienst das Zertifikat
über Cloudflare DNS-01 aus und erneuert es. In diesem Modus ist die öffentliche
Ablage unter `MOUNT_BASE/acme/<projekt>/config/live/dashboard` fest vorgegeben;
`TLS_DIR` wird automatisch abgeleitet. Die Cloudflare-Credentialdatei liegt unter
`SECRETS_BASE/acme-credentials/<projekt>/` und wird read-only eingebunden.
[Einrichtung und Betrieb](letsencrypt-cloudflare.md).
Interne TLS-Dateien werden automatisch verwaltet. PostgreSQL-TLS liegt read-only unter `SECRETS_BASE/storage/<projekt>/postgres-tls`.
Temporäre Laufzeitdateien liegen weiterhin auf tmpfs. Auch die von
Herstellerimages deklarierten `VOLUME`-Pfade werden explizit abgedeckt, damit keine
anonymen Docker-Volumes entstehen.

Vor einem Wechsel zunächst `./cve_mon stop` ausführen, dann `MOUNT_BASE` in `.env`
ändern und `./cve_mon start` ausführen. Der Controller übernimmt ausschließlich die
veränderlichen Daten offline und erhält die Dateirechte. Die bisherigen Daten
bleiben als Rückfallkopie bestehen; vorhandene Ziele werden nicht überschrieben.
Der zuletzt verwendete Speicherort steht unter `.runtime/mount-locations/` im
Repository. Ein Wechsel von `MOUNT_BASE` verlegt keine Secrets. Ein Wechsel von
`SECRETS_BASE` übernimmt die privaten Projektordner und die Standard-Entwicklungs-PKI
offline ohne Schlüsselerneuerung; der alte Stand bleibt als Rückfallkopie erhalten.
Die zugehörige Verwaltungsdatei heißt `<projekt>-secrets.json`. Bei beiden Wechseln
zuerst mit der bisherigen Konfiguration stoppen, danach die `.env` ändern.

Beim nächsten Start werden vorhandene eigene Named Volumes offline und mit
numerischen Eigentümern und Dateirechten in die neuen Verzeichnisse kopiert.
Erst nach erfolgreicher Kopie wird das jeweilige Ziel freigegeben. Laufende
Quellcontainer und fremde Volumes werden abgewiesen; ein bereits vorhandenes
Bind-Verzeichnis wird nicht mit alten Daten überschrieben. Die ursprünglichen
Volumes bleiben als Rückfallkopie erhalten und werden nicht mehr eingebunden.
Ein ausdrücklich bestätigter `reset` löscht auch diese alten Projektvolumes,
damit deren Inhalt beim nächsten Start nicht erneut übernommen wird.

Die Datenverzeichnisse gehören teilweise den numerischen Containerbenutzern.
Rechte nicht pauschal mit `chmod 777` öffnen. Der Controller richtet die benötigten
Eigentümer ein und entfernt beim Reset auch Dateien mit Container-Eigentümern über
einen auf dieses Projektverzeichnis beschränkten Docker-Helfer.

Zunächst werden Frontend und gemeinsames Anwendungsimage anhand ihrer Eingaben geprüft.
Unveränderte Artefakte bleiben im Cache. Sind alle Container, Compose-Einstellungen,
Image-Identitäten, Schema und n8n-Definitionen aktuell, wird das laufende Deployment
beibehalten. Ein ausgefallener Hostcontroller wird wieder bereitgestellt.

Andernfalls übernimmt dieselbe integrierte Startlogik Datenbankvorbereitung und
Migrationen, private Konfiguration und PKI, die drei Anwendungsgruppen mit
Namespace-Freigaben, Postfix, n8n und zuletzt Nginx mit den Dashboard-Assets.
Die vier regulären Herstellerimages werden unverändert bezogen. Es gibt keinen ausgehenden
Proxy und keinen Docker-Socket im Dashboard. Änderungen an Quellen oder Compose
können beim nächsten Start einen regulären Versionsrollout mit Containerersatz
bewirken; ein unveränderter, gesunder Stack wird nicht erneut gestartet.

Bei jedem n8n-Containerstart werden die im Repository enthaltenen Definitionen
importiert und veröffentlicht, bevor Zeitpläne oder Webhooks aktiv werden.
Leere Datenbanken werden automatisch eingerichtet, vorhandene feste Workflow-IDs
aktualisiert und fehlende Definitionen ergänzt. Ein fehlerhafter Abgleich verhindert
den Serverstart. Die Aktualisierung gilt auch bei Docker-Neustarts und benötigt
kein Initialisierungsargument. Eigene, nicht im Repository verwaltete IDs bleiben
bestehen. Importzeitpläne, Pause-Einstellungen, Konten, Passwörter, Inventare sowie
SMTP- und Spracheinstellungen der Anwendung bleiben erhalten.

## Stoppen und Grenzen

`stop` beendet zuerst den eigenen Hostcontroller und dann den Stack. Eine
Prozess-ID wird nur beendet, wenn ihre Kommandozeile genau zum eigenen Controller
und dessen Projektkonfiguration gehört. Eine wiederverwendete fremde PID wird
abgewiesen. Laufende Lösch-/Sicherungsvorgänge werden über die vorhandene
Koordinationssperre abgewartet. Fehlgeschlagene Serverlöschungen werden nicht
wiederholt.

`down` löscht keine Bind-Mount-Daten, Backups, PKI, Benutzerkonfiguration oder Login-Daten.
Andere Compose-Projekte
wie Nextcloud oder Factory werden nicht angesprochen. `logs` akzeptiert ausschließlich
bekannte physische Dienste und logische Worker; Worker derselben Prozessgruppe
werden auf deren gemeinsamen Container abgebildet.

Microservices werden weiterhin über die n8n-Neustartaktion im Dashboard intern
neu gestartet. Der Controller bietet bewusst keinen `restart`-Befehl für Container.
`start`, `build`, `stop` und `down` unterstützen auch `APP_ENV=production` mit den
vorhandenen TLS-/Secret-Prüfungen. Für Server die Vorlage
`configuration/examples/server.env` und die [Serverhinweise](environments.md#produktion)
verwenden. `reset` bleibt auf Entwicklungsprojekte begrenzt.

## Kompletter Datenreset

```sh
./cve_mon --sudo reset --confirm cve-monitoring-dev
./cve_mon --sudo start
```

Der Wert hinter `--confirm` muss exakt dem `COMPOSE_PROJECT_NAME` der gewählten
Konfiguration entsprechen. Ohne passende Bestätigung wird nichts gestoppt oder
gelöscht. Der Reset stoppt den Hostcontroller und die Container, entfernt Container
und Netzwerke und löscht anschließend die eigenen persistenten Bind-Verzeichnisse sowie die
projektspezifischen Laufzeitverzeichnisse. Dabei gehen CVE-Daten, Inventare,
Findings, Benutzerkonten, Passwörter, MFA, Einstellungen, SSH-Schlüssel, n8n-Workflows
und Zugangsdaten, MailHog-Nachrichten und die Postfix-Warteschlange verloren.
Interne Dienstschlüssel und Datenbank-Zertifikate werden beim nächsten Start neu
erzeugt. Der Stack bleibt nach dem Reset gestoppt; der folgende Start mit
`./cve_mon start` richtet ihn neu ein. Benutzerkonten müssen erneut angelegt
werden.

`.env`, die konfigurierten Eingangs-Zertifikate, vorhandene Backups, Quellcode,
Python-/Node-Werkzeuge, Docker-Images und Build-Caches bleiben erhalten. Werte aus
der `.env` (beispielsweise SMTP-Vorgaben) gelten beim nächsten Start wieder.
Der Reset ist keine sichere Löschung vorhandener Sicherungskopien.
Die beiden Koordinations-Lockdateien bleiben ebenfalls erhalten.

Der Befehl prüft die Projektzuordnung vorhandener Container, Datenpfade und alter Volumes und verwendet
kein `prune`. Laufzeitpfade mit Symlinks, Compose-Overrides, Produktionsumgebungen
und ein `PG_WORK_DIR` außerhalb von `SECRETS_BASE` werden abgewiesen.
Fehler beim Stoppen oder Entfernen der Container brechen vor der Datenlöschung ab.
Ein späterer Löschfehler kann einen teilweise zurückgesetzten Zustand hinterlassen;
nach Behebung der Ursache lässt sich derselbe Reset erneut ausführen.

## Optionaler Mailtest

MailHog ist aus dem regulären Compose entfernt. `./cve_mon mail-test start`
aktiviert `infrastructure/compose/mail-test.yml` ausschließlich im Entwicklungsmodus,
`mail-test stop` entfernt den Container. Der normale Healthcheck erwartet sieben
Kerndienste; das Testprofil bleibt optional und wird nicht automatisch gestartet.
