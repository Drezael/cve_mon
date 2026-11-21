# Let’s Encrypt mit Cloudflare DNS-01

CVE Monitor kann das öffentliche Dashboard-Zertifikat mit einem optionalen
Certbot-Container ausstellen und automatisch erneuern. Unterstützt wird derzeit
**ausschließlich DNS-01 über Cloudflare**. Weitere DNS-Provider sind noch nicht
implementiert.

Der Dienst ist standardmäßig ausgeschaltet. Bereits extern bereitgestellte
Zertifikate über `TLS_DIR` bleiben als Alternative verfügbar.

## Voraussetzungen

- Eine eigene registrierte Domain mit einer aktiven, von Cloudflare verwalteten
  autoritativen DNS-Zone.
- `APP_ENV=production` und die gewünschte Dashboard-Domain in `DASHBOARD_DOMAIN`.
- Ein eingeschränkter Cloudflare-API-Token für genau diese Zone.
- Ausgehender HTTPS-Zugang zu Cloudflare und Let’s Encrypt sowie funktionierende
  DNS-Auflösung auf dem Plattformhost beziehungsweise im Ausgangsnetz.
- Eine gültige Kontaktadresse und die bewusste Zustimmung zu den
  [Let’s-Encrypt-Nutzungsbedingungen](https://letsencrypt.org/repository/).

Für die Zertifikatsausstellung ist kein eingehender HTTP- oder HTTPS-Port nötig.
Der Dashboard-Zugang muss nur für die vorgesehenen Benutzer erreichbar sein.
DNS-01 funktioniert daher auch bei einem intern erreichbaren Dashboard unter
einer öffentlich registrierten Domain. Der Challenge-TXT-Eintrag muss im
öffentlichen autoritativen DNS auflösbar sein. Private Namen wie `.test`,
`.localhost` oder reine interne DNS-Zonen eignen sich dafür nicht.

Ein bestehender A-/AAAA-Eintrag oder die Cloudflare-Proxy-Einstellung ersetzt keine
DNS-Zonenberechtigung. Bei einer CAA-Beschränkung muss die Ausstellung durch
Let’s Encrypt erlaubt sein. Diese Integration fordert ausschließlich das Zertifikat
für `DASHBOARD_DOMAIN` an, keine zusätzlichen Dienstnamen und kein Wildcardzertifikat.

## Cloudflare-Token erstellen

1. Im Cloudflare-Dashboard das eigene Profil und **API Tokens** öffnen.
2. **Create Token** wählen und die Vorlage **Edit zone DNS** verwenden oder einen
   passenden benutzerdefinierten Token anlegen.
3. **Zone → DNS → Edit** erlauben.
4. Bei den Zonenressourcen **Include → Specific zone** wählen und ausschließlich
   die Zone der Dashboard-Domain freigeben, beispielsweise `example.org` für
   `dashboard.example.org`.
5. Zusammenfassung kontrollieren und den Token erstellen.
6. Den nur einmal angezeigten Wert geschützt übernehmen.

Keinen Global API Key verwenden. Der Token muss TXT-Einträge für
`_acme-challenge.dashboard.example.org` anlegen und entfernen können. Falls eine
IP-Einschränkung eingerichtet wird, muss sie die tatsächliche ausgehende öffentliche
Adresse des Servers zulassen. Bei einer Token-Ablauffrist rechtzeitig vor deren
Ablauf einen Nachfolger hinterlegen; sonst scheitern spätere Erneuerungen.

Die erforderliche Berechtigung und das INI-Format sind in der
[Certbot-Cloudflare-Dokumentation](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)
beschrieben. Der aktuelle Weg zur Tokenanlage steht bei
[Cloudflare](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/).

## Konfiguration

In der zur Instanz gehörenden privaten `.env` ergänzen:

```dotenv
APP_ENV=production
DASHBOARD_DOMAIN=dashboard.example.org
LETSENCRYPT_ENABLED=true
LETSENCRYPT_EMAIL=admin@example.org
LETSENCRYPT_AGREE_TOS=true
CLOUDFLARE_API_TOKEN=HIER_DEN_EIGENEN_TOKEN_EINTRAGEN
```

Die Beispielwerte ersetzen. Der Token steht als unverzierter Wert hinter `=`;
keine zusätzlichen Anführungszeichen oder Kommentare anhängen. Die `.env` mit
`chmod 600 .env` schützen und niemals versionieren. Bei einer separaten
Konfigurationsdatei deren Pfad und Rechte entsprechend anpassen.

| Variable | Bedeutung |
|---|---|
| `LETSENCRYPT_ENABLED` | `true` aktiviert den optionalen Cloudflare-Dienst; Standard `false` |
| `LETSENCRYPT_EMAIL` | Kontaktadresse für das ACME-Konto |
| `LETSENCRYPT_AGREE_TOS` | Muss für die Aktivierung bewusst auf `true` gesetzt werden |
| `CLOUDFLARE_API_TOKEN` | Auf die benötigte Cloudflare-Zone beschränkter API-Token |
| `DASHBOARD_DOMAIN` | Einziger angeforderter Zertifikatsname |
| `MOUNT_BASE` | Basis für veränderliche ACME-Kontodaten, Zertifikate und Arbeitsdaten |
| `SECRETS_BASE` | Basis für die automatisch erzeugte private Cloudflare-Credentialdatei |

Bei aktivem Dienst leitet der Controller den Zertifikatsordner selbst ab.
`TLS_DIR` wird dann nicht als Eingangsordner verwendet und muss nicht geändert
werden. Ohne den Dienst bezeichnet `TLS_DIR` weiterhin einen extern verwalteten
Ordner mit `fullchain.pem` und `privkey.pem`.

Plugin, Containerpfade, CA-Adresse, Zertifikatsname und Zeitbudgets sind fest im
Repository hinterlegt. Es gibt keinen frei konfigurierbaren Challenge-Typ und
keinen HTTP-Fallback. Das Herstellerimage `certbot/dns-cloudflare` ist mit Version
und Digest in `infrastructure/images.lock.json` festgelegt.

## Erststart und Wechsel einer bestehenden Installation

Bei einer vorhandenen Installation zuerst mit ihrer bisherigen Konfiguration
stoppen. Danach die `.env` ergänzen. Für dieselbe Instanz bleiben Projektname,
`MOUNT_BASE` und `SECRETS_BASE` gleich; bestehende Anwendungsdaten werden nicht
zurückgesetzt.

```bash
./cve_mon config
./cve_mon start
./cve_mon health
./cve_mon logs --tail 100 certbot
```

Für eine separate Instanzkonfiguration:

```bash
./cve_mon --env-file /etc/cve-monitor/server.env config
./cve_mon --env-file /etc/cve-monitor/server.env start
./cve_mon --env-file /etc/cve-monitor/server.env health
./cve_mon --env-file /etc/cve-monitor/server.env logs --tail 100 certbot
```

`config` prüft die Angaben und das Compose-Modell; dabei werden keine Zertifikate
angefordert und keine DNS-Einträge verändert.

`start` führt bei fehlendem beziehungsweise nicht mehr ausreichend gültigem
Zertifikat zunächst einen einmaligen Certbot-Lauf aus. Dieser setzt den
Challenge-TXT-Eintrag, wartet 60 Sekunden auf die DNS-Verbreitung und lässt ihn
prüfen. Erst nach erfolgreicher Ausstellung und der vorhandenen Prüfung von
Kette, Domain, Schlüsselpaar und Restgültigkeit startet der produktive
Dashboard-Zugang. Ein Entwicklungszertifikat wird dafür nicht eingesetzt.

Fehlt die Berechtigung oder scheitert die DNS-Prüfung, meldet der Start den Fehler.
Ein erneuter regulärer Start ist nach Behebung möglich. Weder Datenreset noch
manuelle Löschung von ACME-Kontodaten sind dafür erforderlich.

## Automatische Erneuerung und Aktivierung

Nach dem Plattformstart läuft `cve-certbot` im Hintergrund:

1. Sofort eine Prüfung auf notwendige Ausstellung beziehungsweise Erneuerung.
2. Nach erfolgreicher Prüfung erneut nach zwölf Stunden mit bis zu einer Stunde
   zusätzlicher zufälliger Verzögerung.
3. Bei Fehlern ein weiterer Versuch nach einer Stunde.
4. Certbot erneuert nur bei Fälligkeit; es wird keine Zwangserneuerung pro Prüfung
   angefordert.
5. Der Hostcontroller erkennt geänderte Zertifikate bei seiner Prüfung alle
   60 Sekunden, validiert sie und lädt Nginx neu.

Für eine reguläre Erneuerung ist kein Dashboard- oder Containerneustart nötig.
Das bisherige gültige Zertifikat bleibt bei einem fehlgeschlagenen Versuch erhalten.
Ein fehlgeschlagener oder zu alter Prüfstand wird über den Certbot-Healthcheck
sichtbar; `cve_mon health` berücksichtigt den aktivierten Dienst. Der
Hostcontroller muss für die Übernahme des erneuerten Zertifikats laufen.

`cve_mon stop` stoppt auch den aktivierten Certbot-Dienst. `down` entfernt dessen
Container, erhält aber die Bind-Daten. Für einen vollständigen ruhenden
Sicherungsstand muss auch dieser Dienst beendet sein.

## Erneuerung ausdrücklich testen

Bei laufendem Certbot-Dienst lässt sich mit dem internen Operatorwerkzeug ein
Staging-Test auslösen:

```bash
CVE_ENV_FILE=.env .venv/bin/python -m scripts.infrastructure.acme dry-run
```

Bei einer separaten Konfiguration `CVE_ENV_FILE` entsprechend ersetzen.
Für einen eingerichteten Docker-sudo-Zugang gegebenenfalls `CVE_DOCKER_SUDO=1`
ergänzen. Der Test verwendet Certbots `--dry-run`: Er führt einen echten
DNS-Challenge-Ablauf gegen die Staging-Umgebung durch und setzt dabei temporäre
TXT-Einträge. Er ersetzt kein produktives Zertifikat und benötigt weiterhin einen
funktionierenden Cloudflare-Token. Einen gleichzeitig laufenden regulären
Certbot-Auftrag erst abwarten; beide verwenden dieselbe Certbot-Sperre.

## Ablage und Sicherung

| Hostpfad | Inhalt |
|---|---|
| `MOUNT_BASE/acme/<projekt>/config/` | ACME-Konto, Renewal-Konfiguration, `live/` und `archive/`, Zertifikate und private Zertifikatsschlüssel |
| `MOUNT_BASE/acme/<projekt>/work/` | Certbot-Arbeitsdaten und letzter Prüfstatus |
| `MOUNT_BASE/acme/<projekt>/logs/` | Certbot-Protokolle |
| `SECRETS_BASE/acme-credentials/<projekt>/cloudflare.ini` | Automatisch erzeugte private Credentialdatei mit Modus 0600 |

Der Certbot-Container läuft mit der abgeleiteten Host-UID, schreibgeschütztem
Rootdateisystem, begrenzten Ressourcen und ohne Docker-Socket oder Hostports.
Er erreicht nur das Ausgangsnetz. Der Token wird in eine private Datei geschrieben
und read-only eingebunden; er steht nicht in der Containerumgebung oder in
Certbot-Kommandoargumenten. Die private `.env` bleibt trotzdem eine Secretdatei.

ACME-Konto, Zertifikatsarchiv und private Konfiguration gehören zur vollständigen
Instanzsicherung. Nach einem Hostwechsel nach Möglichkeit den vorhandenen Stand
wiederherstellen, damit nicht unnötig neue Zertifikate angefordert werden.

## Tokenwechsel, Abschalten und Fehlerhilfe

Zum Tokenwechsel einen neuen eingeschränkten Token erstellen, den Wert in der
privaten `.env` ersetzen und `cve_mon start` ausführen. Der Controller aktualisiert
die Credentialdatei. Danach einen Dry-run prüfen und erst anschließend den alten
Token widerrufen. Ein Tokenwechsel erfordert keinen Wechsel des Zertifikatsschlüssels.

Zum Abschalten zunächst mit der bisherigen Konfiguration `cve_mon stop` ausführen.
Danach `LETSENCRYPT_ENABLED=false` setzen und `TLS_DIR` auf einen extern weiter
gepflegten Zertifikatsordner einstellen. Nachfolgende Starts verwenden wieder
ausschließlich diesen Eingangsordner. Das bloße Abschalten organisiert keine
externe Erneuerung und löscht keine alten ACME-Daten.

| Problem | Prüfung |
|---|---|
| Konfiguration wird abgewiesen | Produktionsmodus, `true`/`false`, Kontaktadresse, Zustimmung und vorhandenen Token prüfen |
| Cloudflare meldet fehlende Berechtigung | Richtige Zone, DNS-Edit-Recht, Tokenablauf und IP-Einschränkung kontrollieren |
| Challenge-TXT nicht gefunden | Autoritative Nameserver, richtige Domain, CNAME-/Delegationsbesonderheiten und DNS-Erreichbarkeit prüfen |
| Fehler bei CAA | Die CAA-Vorgaben der Zone müssen Let’s Encrypt erlauben |
| Certbot meldet einen Lock | Einen bereits laufenden Auftrag abwarten; keine Lockdatei eines aktiven Prozesses löschen |
| Certbot ist unhealthy | `logs certbot` prüfen; nach Fehlerbehebung erfolgt automatisch ein weiterer Versuch |
| Neues Zertifikat nicht aktiv | Hostcontrollerstatus, TLS-Prüfung und Nginx-Reload prüfen |
| CA-Limit erreicht | Den genannten Wiederholungszeitpunkt beachten; keine wiederholten Zwangsausstellungen anfordern |

Referenzen: [Certbot-Erneuerung](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates),
[DNS-01 bei Let’s Encrypt](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge),
[Bedienungsanleitung](../bedienungsanleitung.md).
