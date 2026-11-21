# Entwicklungs- und Serverumgebung

Die Standardvorlage `.env.example` verwendet `APP_ENV=production` und ist für
neue Serverinstallationen vorgesehen. Eigene Domain, Hostpfade und Zertifikate
vor dem Start konfigurieren. Bestehende `.env`-Dateien bleiben unverändert.
Für lokale Entwicklung ausdrücklich
[development.env](../../configuration/examples/development.env) verwenden:

```bash
cp configuration/examples/development.env .env
chmod 600 .env
```

Eine vorhandene `.env` dabei nicht überschreiben. Tests und CI wählen die
Entwicklungsvorlage ausdrücklich über `CVE_ENV_FILE`.

Die `.env` enthält ausschließlich externe Anbindungen und Hostintegration.
Interne Strukturen und Laufzeitbudgets sind im
[Architekturvertrag](../architecture/decisions/ADR-0038-external-configuration.md)
und `scripts/infrastructure/policy.py` festgelegt und in Compose verdrahtet.
Interne Schlüssel werden auch dann abgewiesen, wenn ihr bisheriger Standardwert
angegeben wird. Shellvariablen überschreiben keine internen Werte.

| Variable | Bedeutung |
|---|---|
| `APP_ENV` | `development` oder `production` |
| `COMPOSE_PROJECT_NAME` | Eigener Deployment-Namensraum |
| `MOUNT_BASE` | Basis veränderlicher Daten, z.B. `/var/lib/cve-monitor/data` |
| `SECRETS_BASE` | Private Dienstkonfiguration und interne Schlüssel, außerhalb des Checkouts |
| `DASHBOARD_DOMAIN` | Einzige extern erreichbare Anwendungsdomain |
| `INGRESS_BIND_IP` | Hostadresse für das Dashboard; Entwicklung nur Loopback |
| `INGRESS_HTTP_PORT` | Veröffentlichter Dashboard-HTTP-Port, auf Servern 80 |
| `INGRESS_HTTPS_PORT` | Veröffentlichter Dashboard-HTTPS-Port, auf Servern 443 |
| `TLS_DIR` | Extern verwalteter Zertifikatsordner bei deaktivierter automatischer Ausstellung |
| `LETSENCRYPT_ENABLED` | Optionales Cloudflare DNS-01 aktivieren, Standard `false` |
| `LETSENCRYPT_EMAIL`, `LETSENCRYPT_AGREE_TOS` | ACME-Kontakt und ausdrückliche Zustimmung |
| `CLOUDFLARE_API_TOKEN` | Auf die benötigte Cloudflare-Zone beschränkter DNS-Edit-Token |
| `SMTP_HOST` | Optionaler externer SMTP-Server zur Erstkonfiguration |
| `SMTP_PORT` | SMTP-Port, Standard 587 mit STARTTLS |
| `SMTP_SENDER` | Absenderadresse für die SMTP-Erstkonfiguration |
| `SMTP_USERNAME` | Externer SMTP-Benutzer |
| `SMTP_PASSWORD` | Externes SMTP-Passwort; keine internen Dienstpasswörter |

Die Datei ist Daten, kein Shellscript. Keine Shellsubstitution oder eingebetteten
Quotes verwenden. Unbekannte, doppelte und interne Variablen werden abgewiesen.
Host-UID/GID werden automatisch abgeleitet; `PG_WORK_DIR`, Zertifikatsdateinamen,
interne Domains, Sicherheitslimits und Worker-Einstellungen sind keine `.env`-Optionen.

## Produktion

`configuration/examples/server.env` ist die vollständige Servervorlage. Domain,
Hostpfade und externe SMTP-/SSH-Anbindung anpassen und die Datei geschützt speichern.
Nur das Dashboard einschließlich Login und benötigter Dashboard-API wird über
Nginx veröffentlicht. Separate API-, Inventar- und n8n-VHosts sind abgeschaltet;
die internen Dienste haben keine Hostports und werden über Compose/Repo verwaltet.

```dotenv
APP_ENV=production
DASHBOARD_DOMAIN=dashboard.example.org
TLS_DIR=/etc/letsencrypt/live/dashboard.example.org
```

Der Ordner enthält die von Certbot bereitgestellten `fullchain.pem` und `privkey.pem`.
Die üblichen Symlinks nach `../../archive/` werden unterstützt, auch bei rootgeschützten
Dateien: Ein abgeschotteter Docker-Helfer liest sie und erzeugt den minimalen privaten
Dienst-Snapshot. Bei deaktiviertem optionalem Dienst muss ein externes ACME-Werkzeug
Ausstellung und Erneuerung übernehmen. Alternativ stellt der integrierte
Certbot-Dienst Zertifikate ausschließlich über Cloudflare DNS-01 aus und erneuert
sie automatisch. Dann wird `TLS_DIR` aus der festen Ablage unter `MOUNT_BASE`
abgeleitet. Die vollständige Einrichtung steht unter
[Let’s Encrypt mit Cloudflare](letsencrypt-cloudflare.md).
Der Hostcontroller prüft Änderungen alle 60 Sekunden, validiert Domain, Kette und
Schlüsselpaar und lädt Nginx ohne Container-Neustart neu. Ungültige Eingaben ersetzen
kein aktives Zertifikat. Es werden keine privaten TLS-Kopien im Checkout neu erzeugt.

Interne Dienstpasswörter und interne TLS-Verbindungen werden bei einer neuen
Installation automatisch eingerichtet, vorhandene Schlüssel bleiben erhalten.
Diese internen Zertifikate sind keine öffentlichen Dashboard-Zertifikate. Ein
bestehender Development-Bestand mit Development-Markierungen wird nicht stillschweigend
als Produktion übernommen. Für Produktion einen eigenen Projektnamen verwenden.

```sh
./cve_mon --env-file /etc/cve-monitor/server.env config
./cve_mon --env-file /etc/cve-monitor/server.env start
./cve_mon --env-file /etc/cve-monitor/server.env health
./cve_mon --env-file /etc/cve-monitor/server.env stop
```

Jeder n8n-Containerstart aktualisiert und veröffentlicht automatisch die
Workflow-Definitionen aus dem Repository. Dies gilt für die Erstinstallation und
für Docker-Neustarts. Der Releasecontroller bleibt
für signierte Rollouts verfügbar. `reset` ist nur für Entwicklungsprojekte erlaubt.

## Lokaler MailHog

MailHog ist nicht Bestandteil von `compose.yml` und wird nicht beim normalen Start
oder Healthcheck erwartet. Das optionale Profil liegt in `infrastructure/compose/mail-test.yml`:

```sh
./cve_mon mail-test start
./cve_mon mail-test status
./cve_mon mail-test logs
./cve_mon mail-test stop
```

Die Testoberfläche ist ausschließlich unter `http://127.0.0.1:8025` erreichbar.
Für den Test im Dashboard den Capture-Server `mailhog.cve.test:1025` auswählen.
Diese feste Testadresse darf ohne TLS/Authentifizierung verwendet werden; externe
SMTP-Server behalten verifiziertes STARTTLS und Authentifizierung. Mailtests sind
nur im Entwicklungsmodus verfügbar. Stoppen entfernt den Testcontainer und behält
aufgefangene Nachrichten. SMTP-Einstellungen werden nicht automatisch umgeschrieben.

## Persistente Einstellungen

`.env`-SMTP-Werte sind ausschließlich Erstvorgaben. Bereits in PostgreSQL gespeicherte
SMTP-Konfigurationen, auch deaktivierte, haben Vorrang und bleiben beim Neustart erhalten.
Anwendungspräferenzen, Sprache und Workflowzustände werden über das Dashboard verwaltet.
Die anfängliche Sprache ist versionsgebunden Englisch; eine gespeicherte Auswahl bleibt
erhalten. `DEFAULT_LANGUAGE`, `STATUS_COLLECTOR_PAUSED` und ähnliche interne Parameter
werden nicht mehr über `.env` verwaltet.
