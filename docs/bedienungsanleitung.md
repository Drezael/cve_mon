# CVE Monitor – Bedienungsanleitung

Diese Anleitung beschreibt den aktuellen Funktionsumfang von CVE Monitor für
Benutzer, Administratoren und Betreiber. Sie behandelt den Weg von der ersten
Installation bis zur regelmäßigen Inventarisierung, Bewertung und Bearbeitung
von Schwachstellen sowie die wichtigsten Betriebsaufgaben.

Die Bezeichnungen entsprechen der deutschen Oberfläche. Sichtbare Menüpunkte und
Aktionen hängen von den Rechten des angemeldeten Kontos ab. Bei englischer
Spracheinstellung sind die entsprechenden englischen Bezeichnungen zu verwenden.

## Inhalt

1. [Zweck und Benutzergruppen](#1-zweck-und-benutzergruppen)
2. [Schnellstart](#2-schnellstart)
3. [Installation und Erstbetrieb](#3-installation-und-erstbetrieb)
4. [Konfiguration und Zertifikate](#4-konfiguration-und-zertifikate)
5. [Navigation und Rechte](#5-navigation-und-rechte)
6. [Konto und Sprache](#6-konto-und-sprache)
7. [Server und Gruppen](#7-server-und-gruppen)
8. [Inventare](#8-inventare)
9. [Automatische Ansible-Inventarisierung](#9-automatische-ansible-inventarisierung)
10. [CVE-Datenbank und Verarbeitung](#10-cve-datenbank-und-verarbeitung)
11. [Findings bearbeiten](#11-findings-bearbeiten)
12. [Eigene Dashboards](#12-eigene-dashboards)
13. [Mail und Berichte](#13-mail-und-berichte)
14. [Benutzer und Rollen](#14-benutzer-und-rollen)
15. [Systemstatus und Fehlerdiagnose](#15-systemstatus-und-fehlerdiagnose)
16. [Betrieb mit cve_mon](#16-betrieb-mit-cve_mon)
17. [Sicherung und Wiederherstellung](#17-sicherung-und-wiederherstellung)
18. [Wartung und Aktualisierung](#18-wartung-und-aktualisierung)
19. [Daten gezielt entfernen](#19-daten-gezielt-entfernen)
20. [Fehlerhilfe und Referenzen](#20-fehlerhilfe-und-referenzen)

## 1. Zweck und Benutzergruppen

CVE Monitor verknüpft Informationen über überwachte Server und deren installierte
Software mit bekannten Schwachstellen. Inventare enthalten beispielsweise
Betriebssystem, Pakete, Dienste und Docker-Komponenten. Daraus entstehen
Bewertungen und Findings, die im Dashboard geprüft, priorisiert und bearbeitet
werden können.

Der normale Arbeitsablauf lautet:

1. Server anlegen oder ein Inventar mit Hostidentität hochladen.
2. Aktuelle Inventardaten erfassen und übernehmen lassen.
3. CVE-Daten aktualisieren beziehungsweise deren Aktualität prüfen.
4. Die Verarbeitung durch n8n abwarten.
5. Findings prüfen, Zuständigkeiten und Maßnahmen dokumentieren.
6. Nach Änderungen am Zielsystem erneut inventarisieren und bewerten lassen.

| Benutzergruppe | Typische Aufgaben |
|---|---|
| Benutzer | Eigene beziehungsweise freigegebene Server, Inventare, Findings, persönliche Dashboards und Einstellungen verwalten |
| Administrator | Zusätzlich Benutzer, Rollen, Instanzeinstellungen, zentralen Mailversand und Systemstatus verwalten |
| Betreiber | Installation, Hostkonfiguration, Zertifikate, Start/Stop, Datensicherung, Updates und Wiederherstellung durchführen |

Die Standardrollen heißen `user` und `admin`. Ein Administrator besitzt zusätzlich
`user`. Weitere Rollen können in Bestandsinstallationen existieren. Eine Rolle
ersetzt keine notwendige Freigabe für einen fremden Server.

CVE Monitor installiert keine Sicherheitsupdates auf überwachten Servern und
beseitigt keine Schwachstellen automatisch. Die Ansible-Inventarisierung liest
Daten; die eigentliche Behebung erfolgt durch die zuständige Administration des
Zielsystems.

## 2. Schnellstart

### 2.1 Für Benutzer mit vorhandenem Konto

1. Die vom Betreiber mitgeteilte Dashboard-Adresse über HTTPS öffnen.
2. Mit Benutzername und Passwort anmelden; bei eingerichteter MFA zusätzlich den
   Bestätigungscode eingeben.
3. Unter **Server** den eigenen Bestand prüfen.
4. Für einen neuen Bestand **Server anlegen** öffnen.
5. Eine Inventardatei prüfen und speichern oder eine automatische SSH-Erfassung
   einrichten lassen.
6. Nach abgeschlossener Verarbeitung **Findings** öffnen.
7. Auffällige Findings anhand ihrer Evidenz prüfen und die Bearbeitung
   dokumentieren.
8. Unter **Einstellungen** Sprache, Mail und Benachrichtigungen anpassen.

### 2.2 Für Betreiber einer neuen Installation

Die folgenden Befehle werden im Repository ausgeführt:

```bash
cp .env.example .env
chmod 600 .env
./cve_mon setup
./cve_mon config
./cve_mon start
./cve_mon health
```

Die Vorlage verwendet standardmäßig `APP_ENV=production`. Vor `start` die
Dashboard-Domain, Hostpfade und Zertifikatsquelle einrichten. Für ausdrücklich
lokale Entwicklung statt `.env.example` die Vorlage
`configuration/examples/development.env` kopieren; vorhandene `.env`-Dateien nicht
ungeprüft überschreiben.

Vor `start` die `.env` entsprechend [Abschnitt 4](#4-konfiguration-und-zertifikate)
prüfen. Anschließend den ersten Administrator nach
[Abschnitt 3.3](#33-ersten-administrator-anlegen) anlegen.

Es gibt kein Standardkonto und kein Standardpasswort. Die n8n-Workflows werden
beim Containerstart automatisch bereitgestellt; ein Initialisierungsargument ist
nicht erforderlich.

## 3. Installation und Erstbetrieb

### 3.1 Voraussetzungen

Auf dem Plattformhost werden benötigt:

- Linux;
- Docker mit Compose-Plugin;
- Python 3.12 für die lokale Controller-Umgebung;
- ausreichend Speicherplatz für Images, PostgreSQL, CVE-Daten, Inventare und
  temporäre Verarbeitung;
- für einen Neubau Zugriff auf die in den Lockdateien festgelegten Downloadquellen;
- für Serverbetrieb eine passende Dashboard-Domain und gültige TLS-Zertifikate.

`./cve_mon setup` richtet die lokale Python-Umgebung `.venv` ein. Die vorhandenen
Lockdateien und Buildwerkzeuge bestimmen die verwendeten Versionen. Eine Node-
Toolchain für den Dashboard-Build wird bei Bedarf lokal vorbereitet; es gibt
keinen öffentlich erreichbaren Node-Entwicklungsserver im normalen Betrieb.

Docker-Zugriff benötigt der Betreiber auf dem Host. Die Anwendungscontainer
erhalten keinen Docker-Socket. Falls der Host ausschließlich eingerichtetem
passwortlosem Docker-sudo Zugriff erlaubt, die globale Option vor dem Befehl
verwenden:

```bash
./cve_mon --sudo start
./cve_mon --sudo health
```

### 3.2 Lokaler Betrieb und Serverbetrieb

| Punkt | Lokale Entwicklung | Serverbetrieb |
|---|---|---|
| Modus | `APP_ENV=development` | `APP_ENV=production` |
| Bind-Adresse | Üblicherweise `127.0.0.1` | Beispielsweise `0.0.0.0`, passend zur Hostkonfiguration |
| Ports | Standardmäßig 8080/8443 | Üblicherweise 80/443 |
| Dashboard-Name | Beispielsweise `dashboard.example.test` | Eigene erreichbare DNS-Domain |
| Öffentliche Zertifikate | Lokale Testzertifikate möglich | Automatisch mit Cloudflare DNS-01 oder extern bereitgestellt |
| Datenreset per Tool | Mit Projektbestätigung verfügbar | Gesperrt |

Für eine lokale Testdomain kann auf dem Entwicklungsrechner eine passende
Namensauflösung eingerichtet werden, zum Beispiel als Eintrag in `/etc/hosts`:

```text
127.0.0.1 dashboard.example.test
```

Dann lautet die Standardadresse `https://dashboard.example.test:8443`.
Lokale Testzertifikate benötigen gegebenenfalls eine gezielte Vertrauensstellung
für die Test-CA auf dem Entwicklungsgerät. Für Serverbetrieb müssen Domain,
Zertifikatskette und Erreichbarkeit zusammenpassen.

Die Servervorlage liegt unter
[configuration/examples/server.env](../configuration/examples/server.env).
Eine bestehende Entwicklungsinstanz mit Entwicklungsschlüsseln wird nicht
stillschweigend als Produktionsinstanz übernommen. Für eine neue Serverinstallation
einen eigenen Projektnamen und dafür vorgesehene Daten-/Secretverzeichnisse wählen.

### 3.3 Ersten Administrator anlegen

Nach einem erfolgreichen Start und Gesundheitscheck wird das erste
Administratorkonto ausdrücklich angelegt:

```bash
.venv/bin/python scripts/security/bootstrap-admin.py \
  --username administrator \
  --email admin@example.org
```

Benutzername und E-Mail-Adresse anpassen. Das Passwort wird verdeckt und mit
Bestätigung abgefragt. Es gehört nicht als Argument in die Kommandozeile.

Bei einer getrennten Serverkonfiguration dieselbe Datei auch für dieses
Operatorwerkzeug auswählen:

```bash
CVE_ENV_FILE=/etc/cve-monitor/server.env \
  .venv/bin/python scripts/security/bootstrap-admin.py \
  --username administrator \
  --email admin@example.org
```

Falls dafür der eingerichtete Docker-sudo-Zugang erforderlich ist, zusätzlich
`CVE_DOCKER_SUDO=1` setzen. Für kontrollierte Automation ist alternativ
`--password-file` mit einer geschützten regulären Datei möglich; Details stehen
in [Erstadministrator](operations/initial-administrator.md).

Danach im Dashboard anmelden, die Kontosicherheit prüfen und den ersten Server
aufnehmen. Das Bootstrapwerkzeug ist kein Verfahren, um einen verlorenen
Administratorzugang durch ein zusätzliches Konto zu umgehen.

## 4. Konfiguration und Zertifikate

### 4.1 Aufgabe der .env

Die `.env` beschreibt externe Anbindungen und die Hostumgebung. Interne
Dienstadressen, Datenbankrollen, Containerports und Workerbudgets sind im
Repository beziehungsweise in Compose festgelegt.

| Variable | Bedeutung |
|---|---|
| `APP_ENV` | Betriebsmodus: `development` oder `production` |
| `COMPOSE_PROJECT_NAME` | Eindeutiger Projektname der Installation |
| `MOUNT_BASE` | Basisverzeichnis für veränderliche Containerdaten |
| `SECRETS_BASE` | Basisverzeichnis für Schlüssel und private Dienstkonfiguration |
| `INGRESS_BIND_IP` | Hostadresse, an die der Dashboard-Eingang gebunden wird |
| `INGRESS_HTTP_PORT` | Veröffentlichter HTTP-Port |
| `INGRESS_HTTPS_PORT` | Veröffentlichter HTTPS-Port |
| `DASHBOARD_DOMAIN` | DNS-Name des Dashboards, ohne Schema oder Pfad |
| `TLS_DIR` | Externer Zertifikatsordner, wenn die automatische Ausstellung ausgeschaltet ist |
| `LETSENCRYPT_ENABLED` | Optionalen Certbot-Dienst für Cloudflare DNS-01 aktivieren |
| `LETSENCRYPT_EMAIL` | Kontaktadresse für das ACME-Konto |
| `LETSENCRYPT_AGREE_TOS` | Bewusste Zustimmung zu den Let’s-Encrypt-Nutzungsbedingungen |
| `CLOUDFLARE_API_TOKEN` | Auf die benötigte DNS-Zone beschränkter API-Token |
| `SMTP_HOST` | Externer SMTP-Hostname für die initiale zentrale Mailkonfiguration |
| `SMTP_PORT` | SMTP-Port, üblicherweise 587 mit STARTTLS |
| `SMTP_SENDER` | Absenderadresse für die initiale Mailkonfiguration |
| `SMTP_USERNAME` | SMTP-Benutzername |
| `SMTP_PASSWORD` | SMTP-Passwort |

Die SMTP-Angaben können eine noch nicht vorhandene zentrale Konfiguration
initialisieren. Eine bereits in der Datenbank gespeicherte zentrale
SMTP-Konfiguration wird dadurch nicht überschrieben. Änderungen an einer laufenden
Instanz deshalb in den zentralen Mail-Einstellungen vornehmen und deren
Anwendungsstatus prüfen.

Die `.env` enthält möglicherweise Zugangsdaten: geschützt speichern und nicht
in Git einchecken. Als Produktivvorlage dient `.env.example`; für lokale Tests gibt es
`configuration/examples/development.env`. Beide enthalten nur Beispielwerte.

### 4.2 Datenablage

Persistente Containerdaten verwenden Bind-Mounts. Unter `MOUNT_BASE` entstehen
Dienst- und Projektverzeichnisse, etwa für PostgreSQL, n8n und die Mailwarteschlange.
`SECRETS_BASE` enthält private Schlüssel, Credentials und dienstbezogene private
Konfigurationen. Statische schreibgeschützte Dateien bleiben im Repository.

Beispiel für eine einzelne Installation:

```dotenv
MOUNT_BASE=/mnt/cve-monitor/data
SECRETS_BASE=/mnt/cve-monitor/secrets
```

Ein eigenes Basisverzeichnis erleichtert die Zuordnung und Sicherung. Diese
Pfade sind Hostpfade; im Container bleiben die internen Pfade fest vorgegeben.

Vor einer Änderung der Basisverzeichnisse den Stack stoppen. Der Controller
übernimmt vorhandene Bestände beim nächsten kontrollierten Start; ursprüngliche
Bestände bleiben als Rückfallkopie erhalten. Nach dem Wechsel Datenbestand und
Gesundheit prüfen. Alte Kopien erst nach einer geprüften Sicherung und erfolgreicher
Kontrolle gezielt bereinigen.

### 4.3 Let’s-Encrypt-Zertifikate

Für automatische Ausstellung und Erneuerung im Serverbetrieb den optionalen
Cloudflare-Dienst aktivieren:

```dotenv
DASHBOARD_DOMAIN=dashboard.example.org
LETSENCRYPT_ENABLED=true
LETSENCRYPT_EMAIL=admin@example.org
LETSENCRYPT_AGREE_TOS=true
CLOUDFLARE_API_TOKEN=HIER_DEN_EIGENEN_TOKEN_EINTRAGEN
```

Die Werte anpassen und den Token auf **Zone → DNS → Edit** für genau die
betroffene Cloudflare-Zone beschränken. Die `.env` bleibt privat mit Modus 0600.
Die Zustimmung zu den Nutzungsbedingungen bewusst erteilen.

Verwendet wird ausschließlich **DNS-01 über Cloudflare**. Certbot setzt den
Challenge-TXT-Eintrag über die DNS-API und entfernt ihn wieder. Für diese Prüfung
muss kein eingehender Port geöffnet werden. Andere Provider und HTTP-Challenges
sind nicht implementiert. Der öffentlich auflösbare DNS-Zonenbestand muss über
Cloudflare verwaltet werden; die Dashboard-Adresse selbst darf intern erreichbar
sein.

`cve_mon start` fordert das erste Zertifikat vor dem produktiven TLS-Start an und
startet danach den Erneuerungsdienst. Certbot prüft sofort und anschließend alle
zwölf Stunden mit bis zu einer Stunde zusätzlicher Zufallsverzögerung; Fehler
werden nach einer Stunde erneut versucht. Die Zertifikatsablage unter `MOUNT_BASE`
und die Credentialdatei unter `SECRETS_BASE` werden automatisch abgeleitet.
`TLS_DIR` muss in diesem Modus nicht gepflegt werden.

Ohne diesen Dienst weiterhin einen extern verwalteten Ordner verwenden:

```dotenv
LETSENCRYPT_ENABLED=false
TLS_DIR=/etc/letsencrypt/live/dashboard.example.org
```

Der Ordner muss `fullchain.pem` und `privkey.pem` bereitstellen. Die üblichen
Certbot-Symlinks zum zugehörigen `archive`-Verzeichnis werden unterstützt.
In diesem Modus stellt das externe ACME-Werkzeug die Zertifikate aus und erneuert
sie. Einzelne Zertifikatspfade pro Dienst werden nicht in der `.env` gepflegt.

In beiden Fällen prüft der Hostcontroller Änderungen alle 60 Sekunden. Nach
Prüfung von Domain, Zertifikatskette und Schlüsselpaar wird Nginx neu geladen.
Ungültige Dateien ersetzen kein gültiges aktives Zertifikat. Interne
Dienstzertifikate und Schlüssel werden getrennt durch die Dienstvorbereitung
verwaltet.

Tokenanlage, Erststart, Testerneuerung, Ablage, Tokenwechsel und Fehlerhilfe:
[Let’s Encrypt mit Cloudflare DNS-01](deployment/letsencrypt-cloudflare.md).

### 4.4 Erreichbarkeit

Von außen wird ausschließlich der Dashboard-Eingang veröffentlicht, einschließlich
Anmeldung und benötigter Dashboard-API. n8n, PostgreSQL, Mailrelay und Worker haben
keine veröffentlichten Hostports. Es gibt keine zusätzlichen öffentlichen n8n-,
Inventar- oder API-Domains.

Die technische Konfiguration dieser Dienste erfolgt über Compose und Repository.
Für reguläre Benutzer ist keine direkte Anmeldung an n8n erforderlich.

## 5. Navigation und Rechte

Nach dem Login stehen abhängig von den Berechtigungen folgende Bereiche bereit:

| Bereich | Verwendung |
|---|---|
| **Übersicht** | Kennzahlen, Verteilungen und Finding-Verlauf; für Administratoren auch CVE-Datenbank und zentrale Steuerung |
| **Dashboards** | Persönliche beziehungsweise ausdrücklich geteilte YAML-Dashboards |
| **Server** | Sichtbarer Serverbestand, Details, Inventare und Scan-Aktionen |
| **Gruppen** | Persönliche Zusammenstellung eigener beziehungsweise sichtbarer Server |
| **Findings** | Schwachstellenlisten, Evidenz und Bearbeitung |
| **Einstellungen** | Persönliche Einstellungen und jeweils freigegebene Verwaltungsfunktionen |
| **Systemstatus** | Geschützte Diagnose- und Statusansicht für Administratoren |

Ein fehlender Menüpunkt bedeutet häufig, dass die notwendige Berechtigung fehlt.
Ein direkter URL-Aufruf erweitert die Rechte nicht. Wurde eine Freigabe entzogen,
kann auch eine bereits geöffnete Ansicht beim nächsten Zugriff abgewiesen werden.

Formulare können eine Begründung oder erneute Bestätigung der Identität verlangen.
Bei einem Versionskonflikt den aktuellen Stand neu laden und die Änderung erneut
prüfen. Mehrfaches blindes Absenden löst den Konflikt nicht.

## 6. Konto und Sprache

### 6.1 Anmeldung und Abmeldung

Die Dashboard-Domain des Betreibers verwenden und mit dem eigenen Konto anmelden.
Bei aktivierter MFA folgt die Abfrage des sechsstelligen Authenticator-Codes.
Über **Abmelden** wird die aktuelle Sitzung beendet.

Unter **Einstellungen → Kontosicherheit** lassen sich das eigene Passwort ändern
und alle eigenen Sitzungen abmelden. Bei einer Passwortänderung die im Formular
angegebenen Anforderungen beachten; das aktuelle Formular verlangt mindestens
15 und höchstens 256 Zeichen.

### 6.2 Optionale Zwei-Faktor-Anmeldung

1. **Einstellungen → Kontosicherheit** öffnen.
2. Die Einrichtung der optionalen Zwei-Faktor-Anmeldung starten.
3. Den angezeigten Einrichtungsschlüssel in einer Authenticator-App hinterlegen.
4. Den aktuellen sechsstelligen Code zur Bestätigung eingeben.
5. Die anschließend ausgegebenen Recovery-Codes getrennt aufbewahren.
6. Bei späterer Anmeldung Passwort und Authenticator-Code verwenden.

MFA ist optional. Eine begonnene Einrichtung kann abgebrochen werden. Bei Verlust
des zweiten Faktors einen noch gültigen Recovery-Code über den angebotenen
Wiederherstellungsweg verwenden. Gegebenenfalls ist danach die Einrichtung eines
neuen Faktors erforderlich. Ohne verbleibende Codes den verantwortlichen Betreiber
kontaktieren; es gibt kein allgemeines Standardpasswort oder pauschales MFA-Bypass.

### 6.3 Sprache

Unter **Einstellungen → Sprache** Deutsch, Englisch oder die angebotene
Instanzvorgabe wählen. Die persönliche Wahl wird im Konto gespeichert und gilt
auch auf anderen Geräten. Berechtigte Administratoren legen die Vorgabe unter
**Einstellungen → Instanzeinstellungen** fest.

## 7. Server und Gruppen

### 7.1 Server manuell anlegen

1. **Server** öffnen und **Server anlegen** wählen.
2. Eine eindeutige, verständliche Serverbezeichnung eintragen.
3. Beschreibung und Umgebung ergänzen, beispielsweise `Produktion` oder `Test`.
4. Kritikalität und Erreichbarkeit fachlich auswählen.
5. Optional bereits eine Inventardatei laden und deren Vorschau prüfen.
6. Mit **Server speichern** bestätigen.

Die Kritikalität beschreibt die Bedeutung des Servers. Die Erreichbarkeit
beschreibt dessen Exposition, etwa intern oder aus dem Internet erreichbar.
Beide Angaben sollten die tatsächliche Umgebung abbilden.

Eine Anlage ohne Inventar erzeugt zunächst Stammdaten. Für eine technische
Sicherheitsbewertung werden passende Inventardaten benötigt. Die automatische
SSH-Erfassung kann nach der Serveranlage eingerichtet werden.

### 7.2 Serverdetails und Berechtigungen

In der Serverliste den gewünschten Server öffnen. Je nach Rechten sind Stammdaten,
Inventarstand, Pakete, Container, Findings und Bearbeitungsaktionen sichtbar.
Administratoren beziehungsweise entsprechend berechtigte Konten können Freigaben
über die Server-ACL verwalten.

Lesen, Inventarübernahme und Finding-Bearbeitung sind getrennte Rechte. Bei einer
Freigabe deshalb ausdrücklich prüfen, welche Aufgaben die andere Person erledigen
soll. Die bloße Kenntnis einer Server-ID genügt nicht für einen Zugriff.

### 7.3 Gruppen verwenden

1. **Gruppen** öffnen.
2. **Gruppe anlegen** auswählen und einen Namen sowie optional eine Beschreibung
   vergeben.
3. Die gewünschten Server zuordnen.
4. Den Bestand über die Gruppe filtern und bei Bedarf die Zuordnung ändern.

Die Gruppen sind persönlich. Ein Server kann mehreren eigenen Gruppen angehören.
Gruppenzuordnungen vergeben keine Serverrechte. Wenn ein Server später nicht mehr
freigegeben ist, macht eine gespeicherte Gruppenzuordnung ihn nicht wieder sichtbar.
Eine Gruppenlöschung ist keine Serverlöschung.

### 7.4 Einen Scan auslösen

Über **Scan** in der Serverliste oder im Serverdetail einen neuen Bewertungsauftrag
anfordern. Dafür müssen die erforderlichen Rechte und ein geeigneter Inventarstand
vorliegen. Die Meldung **Vollscan wurde über n8n eingereiht** bestätigt den Auftrag;
sie bedeutet nicht, dass die Bewertung bereits abgeschlossen ist.

Ein Scan bewertet einen vorhandenen Inventarstand. Wurde Software auf dem Zielhost
verändert, zuerst ein neues Inventar erfassen oder hochladen. Ein Scan allein
stellt keine neue SSH-Verbindung zur Aktualisierung des Bestands her.

## 8. Inventare

### 8.1 Was eine Inventardatei enthält

Unterstützt werden die im Uploaddialog ausgewiesenen JSON-Schemaversionen.
Die aktuelle integrierte Erfassung erzeugt Format 1.3. Formate 1.2 und 1.3 enthalten
Hostidentität; die älteren Formate 1.0 und 1.1 verwenden eine vorhandene interne
Server-ID.

Eine Datei kann unter anderem enthalten:

- Hostname und stabile Monitoring-ID;
- Betriebssystem, Architektur und Hardwareinformationen;
- installierte Pakete und Dienste;
- Docker-Container und lokale Images;
- Softwareinventare von Images, Laufzeitdateisystemen und ausgewählten Mounts;
- Angaben zur Vollständigkeit und Fehlerdiagnosen.

Die Anzeige einer Teilmenge bedeutet nicht, dass alle übrigen Bereiche geprüft
wurden. **Nicht erfasst**, **fehlgeschlagen** und **vollständig erfasst** sind
unterschiedliche Zustände.

### 8.2 Datei im Dashboard übernehmen

1. Unter **Server** den Weg **Server anlegen** öffnen und dort
   **Serverinventar laden (optional)** verwenden.
2. Eine UTF-8-JSON-Datei mit einfachem Dateinamen wählen, etwa `inventory.json`.
3. Die vollständig geladene Vorschau prüfen: Host, Betriebssystem, Paket- und
   Containerzahlen sowie bei Bedarf das vollständige JSON.
4. Server-Stammdaten prüfen beziehungsweise ergänzen.
5. Falls erforderlich einen vorhandenen Server bewusst zuordnen.
6. Mit **Server speichern** bestätigen.
7. Den Empfangs- und Verarbeitungsstatus verfolgen.

Das Laden einer Datei ist zunächst nur ein Entwurf im Browser. Erst das Speichern
überträgt und übernimmt die Daten. **Inventar verwerfen** entfernt den Entwurf.
Die maximal zulässige Dateigröße wird vom Uploaddialog beziehungsweise vom Server
vorgegeben; übergroße und unbekannte Formate werden abgewiesen.

Bei Format 1.2/1.3 kann ein noch unbekannter Server mit geeigneter Hostidentität
angelegt werden. Dafür sind die entsprechenden Inventarverwaltungsrechte nötig.
Weitere Uploads derselben Monitoring-ID gehören zum bestehenden Server. Bei
widersprüchlichen Identitäten wird eine Prüfung beziehungsweise ausdrückliche
Zuordnung erforderlich. Eine ID nicht beliebig ändern, um einen Konflikt zu umgehen.

Die Annahmebestätigung bedeutet einen gespeicherten Empfang, nicht bereits einen
fertigen neuen Snapshot oder ein abgeschlossenes Matching. n8n gibt die weiteren
Schritte frei. Derselbe bestätigte Upload soll keine doppelten Inventare erzeugen.

### 8.3 Lokale Inventardatei erzeugen

Für eine lokale Erfassung dieselben repository-eigenen Playbooks verwenden wie
im Container. Eine private Konfiguration nach
[ansible-target.json](../configuration/examples/ansible-target.json) vorbereiten.
Konfiguration und private Credential-Dateien müssen dem ausführenden Benutzer
gehören und entsprechend geschützt sein.

```bash
.venv/bin/python -m scripts.ansible.manage probe \
  --config /private/target.json

.venv/bin/python -m scripts.ansible.manage test \
  --config /private/target.json

.venv/bin/python -m scripts.ansible.manage collect \
  --config /private/target.json \
  --output /private/inventory.json
```

Nach `probe` den ausgegebenen Hostkey unabhängig am Zielsystem prüfen und in der
privaten Konfiguration bestätigen. `test` und `collect` verwenden anschließend
diesen bestätigten Schlüssel. Die erzeugte Datei kann im Dashboard übernommen
werden. Geheimnisse als geschützte Dateien referenzieren, nicht in CLI-Argumente
schreiben. [Lokale Ansible-Anleitung](../integrations/ansible/README.md).

Die [Beispielinventare](../examples/inventories/README.md) enthalten synthetische
Daten mit festen IDs und Zeitpunkten. Sie dienen zur Orientierung; für den eigenen
aktuellen Serverbestand die reguläre Erfassung verwenden.

## 9. Automatische Ansible-Inventarisierung

### 9.1 Zielhost vorbereiten

Am besten einen eigenen Benutzer wie `cve-inventory` auf dem Zielhost anlegen.
Dieser Benutzer erhält SSH-Zugang und ausschließlich die für die Erfassung
benötigten Leserechte. Keine sudo-Rechte und keinen Root-Zugang vergeben.

Die feste Erfassung installiert keine Pakete oder Werkzeuge und verändert keine
Systemkonfiguration, Dienste, Images oder Container. Es werden auch keine
Abfragebefehle in überwachten Containern ausgeführt. Private temporäre
Arbeitsdateien für die Ausführung beziehungsweise SBOM-Verarbeitung sind möglich
und werden nach dem Lauf entfernt.

Ein Administrator muss gegebenenfalls vorab folgende Voraussetzungen bereitstellen:

| Erfassungsumfang | Voraussetzung auf dem Zielhost |
|---|---|
| SSH und Basisinventar | SSH-Server, Python 3, lesbare Systeminformationen |
| Paketdaten | Je nach Distribution beispielsweise `python3-apt` oder `python3-rpm` |
| Docker-Metadaten | Docker-CLI und ein beschränkter Docker-API-Lesezugang |
| Docker-Softwareanalyse | Syft unter `/usr/local/bin/syft` |
| Ressourcenbegrenzung der Analyse | `/usr/bin/prlimit`, üblicherweise aus util-linux |
| Anwendungsmounts | Gezielte Leserechte auf die ausdrücklich ausgewählten Hostpfade |

Syft-Version und Release-Prüfsummen stehen in
[syft.lock.json](../scripts/container_inventory/syft.lock.json).

Der normale Docker-Socket beziehungsweise eine Mitgliedschaft in der üblichen
`docker`-Gruppe ist kein beschränkter Lesezugang. Für die Erfassung muss ein
Administrator einen entsprechend autorisierten lokalen Endpunkt unter
`/run/cve-monitoring/docker-readonly.sock` bereitstellen. Der Collector verwendet
keinen unbeschränkten Socket als Ersatz. Die erlaubten Leseoperationen und der
Aufbau sind in [Automatische Servererfassung](operations/managed-ansible.md)
beschrieben.

Alle Zielnetze und Zieladressen sind grundsätzlich zulässig. Routing, Firewall,
SSH-Port und Hostkey müssen zur tatsächlichen Verbindung passen. Die Freigabe
einer Adresse ersetzt keine Netzwerkverbindung oder Zugriffsberechtigung.

### 9.2 Verbindung im Dashboard einrichten

1. Den Server anlegen und dessen Bearbeitungs-/Verwaltungsansicht öffnen.
2. Den Bereich **Automatische Erfassung mit Ansible** aufrufen.
3. Hostname oder IP-Adresse und SSH-Port eintragen.
4. Den beschränkten Zielbenutzer angeben.
5. **SSH-Schlüssel** oder **Passwort** als Anmeldemethode auswählen.
6. Schlüssel beziehungsweise Passwort und optional eine Schlüssel-Passphrase
   eingeben. Gespeicherte Geheimnisse werden später nicht angezeigt.
7. Optional die zu analysierenden Anwendungsmounts angeben.
8. Mit **Verbindung speichern** bestätigen.
9. **Hostkey auslesen** anfordern und den Lauf abwarten.
10. Den angezeigten Schlüssel/Fingerprint mit dem Zielhost vergleichen und
    **Hostkey bestätigen** verwenden.
11. **Verbindung testen** anfordern und das Ergebnis prüfen.
12. Mit **Jetzt erfassen** einen ersten Inventarlauf anfordern.
13. Den Laufstatus und anschließend den neuen Inventarstand kontrollieren.

Auch Hostkey-Abfragen und Verbindungstests werden über n8n freigegeben. Ein
wartender Auftrag bedeutet nicht sofort einen SSH-Fehler. Bei nicht laufender
zentraler Steuerung zuerst deren Zustand prüfen.

Ändern sich Host oder Port, ist eine neue Hostkey-Bestätigung erforderlich.
Ein unerwarteter Schlüsselwechsel muss am Zielsystem geklärt werden. Einen
unbekannten neuen Schlüssel nicht allein wegen einer Fehlermeldung bestätigen.

### 9.3 Regelmäßige Erfassung

**Regelmäßig erfassen** aktivieren und das Intervall in Minuten festlegen.
Zulässig sind fünf Minuten bis sieben Tage. Nach dem Speichern werden fällige
Läufe durch n8n geplant. In der Liste **Letzte Läufe** stehen unter anderem
Anforderungszeit, Aktion, Status, Fehlercode und n8n-Ausführungsbezug.

Wenn sich Zugangsdaten ändern, das Profil aktualisieren und erneut testen.
Leere Geheimnisfelder behalten gespeicherte Werte bei; sie zeigen nicht an,
dass kein Passwort oder Schlüssel hinterlegt wäre.

### 9.4 Docker-Ergebnisse einordnen

Syft liest lokal vorhandene Images; ein fehlendes Image wird nicht aus einer
Registry nachgeladen. Bei Änderungen am Containerdateisystem kann ein lesender
Export untersucht werden. Anwendungsmounts werden nur nach ausdrücklicher Auswahl
und mit vorhandenen Leserechten einbezogen.

Fehlende Werkzeuge oder Rechte können zu unvollständigen Softwareinventaren
führen. Das ist keine Bestätigung eines schwachstellenfreien Containers. Der
CVE-Abgleich erfolgt anschließend im Monitor auf Grundlage der gelieferten Daten.

## 10. CVE-Datenbank und Verarbeitung

### 10.1 Datenstand prüfen

Administratoren finden auf **Übersicht** die Bereiche **CVE-Datenbank** und
**Zentrale Steuerung · n8n**. Die Anzeige unterscheidet unter anderem eingelesene
Dokumente, gespeicherte Daten und noch ausstehende Verarbeitungspakete.

Ein aktueller Download ist noch kein Nachweis eines abgeschlossenen Imports,
Suchindexaufbaus oder Inventarabgleichs. Quellenstatus, letzte erfolgreiche
Verarbeitung und offene Aufträge gemeinsam betrachten.

### 10.2 Eine Aktualisierung anfordern

1. **Übersicht** öffnen.
2. Den aktuellen Stand im Bereich **CVE-Datenbank** prüfen.
3. **Datenbank aktualisieren** betätigen.
4. Die Bestätigung und Warteschlangenposition abwarten.
5. Fortschritt und Abschluss in der automatisch aktualisierten Anzeige verfolgen.
6. Danach den Stand der weiteren Verarbeitungsschritte kontrollieren.

Der Erstimport kann erheblich mehr Zeit und Speicher benötigen als spätere
inkrementelle Aktualisierungen. Ein sichtbarer wartender Auftrag ist kein Grund,
fortlaufend neue identische Aufträge anzulegen.

Der zentrale CVE-Import verwendet CVEProject/cvelistV5 über Git. Zusätzliche
bereitgestellte Quelleninformationen, etwa KEV oder EPSS, haben eigene
Aktualitätsangaben. Nicht konfigurierte oder deaktivierte Quellen sind entsprechend
zu unterscheiden. EPSS-Daten ersetzen keine CVE- oder Inventardaten.

### 10.3 Automatische Updates und Ablaufsteuerung

Im Bereich **Zentrale Steuerung · n8n** können berechtigte Administratoren
automatische Updates und das Prüfintervall verwalten. **Zeitplan speichern**
übernimmt die gewählte Einstellung. Die Ansicht zeigt wartende, eingereihte,
laufende und fehlgeschlagene Verarbeitungsschritte sowie letzte n8n-Freigaben.

Für einzelne noch aktive Abläufe stehen je nach Zustand **Pausieren**,
**Fortsetzen** und **Abbrechen** bereit. Eine Pause beziehungsweise ein Abbruch
ist keine Rücknahme bereits abgeschlossener Verarbeitung. Bei einem Abbruch
bleiben bereits gespeicherte CVEs und Inventare erhalten.

n8n arbeitet intern. Die Workflow-Definitionen aus dem Repository werden bei
jedem Start des n8n-Containers automatisch aktualisiert und veröffentlicht,
bevor dessen Zeitpläne und Webhooks starten. Gespeicherte Zeitplan- und
Pause-Einstellungen der Anwendung bleiben dabei erhalten.

## 11. Findings bearbeiten

### 11.1 Liste und Filter

Unter **Findings** den eigenen beziehungsweise freigegebenen Bestand öffnen.
Die Liste kann unter anderem nach CVE, Priorität, Lebenszyklus, technischer
Bewertung, KEV-Bezug und überfälliger Frist eingegrenzt werden. Sortierung und
Pagination helfen bei größeren Beständen.

| Information | Bedeutung für die Bearbeitung |
|---|---|
| Priorität | Handlungsreihenfolge anhand der vorhandenen Risikobewertung |
| Technische Bewertung | Beispielsweise betroffen, nicht betroffen oder nicht bewertbar |
| Lebenszyklus | Beispielsweise offen, in Bearbeitung, behoben oder geschlossen |
| CVSS | Technischer Schweregrad mit zugehöriger Version/Quelle |
| EPSS | Wahrscheinlichkeitsschätzung mit eigenem Datenstand, keine bestätigte Ausnutzung |
| KEV | Hinweis auf den bekannten Ausnutzungskontext der zugehörigen Quelle |
| Frist | Termin beziehungsweise Überfälligkeit aus den geltenden Vorgaben |

**Nicht bewertbar** ist keine Entwarnung. Fehlende Paketversionen, unvollständige
Inventare oder mehrdeutige Zuordnungen müssen zuerst geklärt werden.

### 11.2 Einen Befund prüfen

1. Den Befund in der Liste öffnen.
2. Betroffenen Server und Komponentenbezug kontrollieren.
3. Installierte Versionen und technische Entscheidungsgründe lesen.
4. Den verwendeten Inventarstand und die Quellen-/Verarbeitungsstände prüfen.
5. Vorhandene Episoden, Notizen und Historie ansehen.
6. Erst danach eine fachliche Bearbeitungsentscheidung treffen.

Die Anwendung zeigt die vorhandene Evidenz. Daraus nicht eigenständig eine vom
Produkt nicht ausgewiesene Fixversion ableiten. Bei Distributionen außerdem
Herstellerhinweise und mögliche Backports berücksichtigen.

### 11.3 Triage, Zuständigkeit und Notizen

Über die angebotene Bearbeitungsaktion können berechtigte Konten beispielsweise:

- **Triage** dokumentieren, etwa Prüfung beginnen oder Betroffenheit bestätigen;
- einen **Bearbeiter zuweisen**;
- eine **Notiz hinzufügen**;
- eine **Fehlalarmprüfung dokumentieren**;
- eine **Maßnahme dokumentieren**;
- eine **Risikoausnahme beantragen**.

Die Formulare verlangen die jeweils notwendigen Angaben und gegebenenfalls eine
Begründung oder erneute Bestätigung. Notizen sollten Beobachtung, Entscheidung
und nächste Schritte verständlich festhalten, aber keine Zugangsdaten enthalten.

### 11.4 Fehlalarm, Risikoausnahme und Abschluss

Ein vermuteter Fehlalarm wird zuerst dokumentiert und geprüft. **Fehlalarm
bestätigen** steht nur bei passenden Rechten und Voraussetzungen bereit.
Eine Risikoausnahme ist eine bewusste zeitlich begrenzte Entscheidung; sie behebt
keinen technischen Fehler. Entsprechend berechtigte Personen können Ausnahmen
genehmigen, ablehnen oder widerrufen.

Nach einer Maßnahme ein neues Inventar erfassen und den Abgleich abwarten.
**Finding abschließen** ist von den geltenden fachlichen Voraussetzungen abhängig.
Eine spätere erneut betroffene Evidenz kann ein Finding wieder öffnen. Die
Historie bleibt erhalten.

## 12. Eigene Dashboards

Unter **Dashboards** können persönliche Übersichten aus YAML erstellt werden.
Diese Einstellungen sind von der fest programmierten allgemeinen **Übersicht**
zu unterscheiden.

### 12.1 Dashboard erstellen oder importieren

1. **Dashboards** öffnen und **Erstellen** wählen.
2. Einen Titel und die gewünschte YAML-Konfiguration eingeben oder eine Datei
   importieren.
3. **Prüfen und Vorschau** verwenden.
4. Inhalte und sichtbare Daten prüfen.
5. Mit **Speichern** dauerhaft übernehmen.
6. Das Dashboard anschließend aus der Auswahl öffnen.

Eine ausführliche Vorlage liegt unter
[security-overview.yaml](../configuration/dashboards/security-overview.yaml).
Ein kleines Beispiel:

```yaml
version: 1
title: Mein Sicherheitsdashboard
layout:
  columns: 2
refresh_interval_seconds: 0
widgets:
  - id: servers
    type: metric
    title: Aktive Server
    metric: active_servers
  - id: findings
    type: findings
    title: Offene kritische Findings
    limit: 10
    filters:
      priority: critical
      lifecycle: open
```

Jedes Widget benötigt eine eindeutige ID. Angeboten werden unter anderem
Kennzahlen, Verteilungen, Server- und Findinglisten, Text, Inventarqualität und
Verläufe. Administrative Widgets für Datenbank oder zentrale Steuerung verlangen
zusätzliche Rechte.

### 12.2 Aktualisieren, teilen und exportieren

**Aktualisieren** lädt die Daten neu. Standardmäßig ist automatische
Aktualisierung ausgeschaltet; über YAML können unterstützte Intervalle
konfiguriert werden. **YAML exportieren** lädt die Konfiguration herunter.

Über **Teilen** können Besitzer aktive Benutzer ausdrücklich freigeben. Dadurch
werden Layout und Konfiguration geteilt, keine zusätzlichen Server- oder
Findingrechte. Empfänger sehen weiterhin nur ihren berechtigten Datenbestand.
Ein geteiltes Dashboard kann als eigene Kopie gespeichert werden; das Original
bleibt beim Eigentümer.

Kommentare und YAML-Quelltext werden gespeichert. Ein Versionskonflikt darf einen
lokalen Entwurf nicht unbesehen überschreiben. Ein Dashboard zu löschen entfernt
seine Konfiguration, keine Server oder Findings.

Die [ausführliche Dashboard-Anleitung](dashboard/custom-dashboards.md) beschreibt
alle zehn Widgettypen, acht Kennzahlen, sechs Verteilungen, sämtliche Filter,
Berechtigungen und Ressourcenquellen. Importierbare Vorlagen stehen für
[alle Ressourcen](../configuration/dashboards/all-resources.yaml) und den
[administrativen Betrieb](../configuration/dashboards/operations.yaml) bereit.

## 13. Mail und Berichte

### 13.1 Persönliche Empfänger und SMTP-Auswahl

Unter **Einstellungen → Meine Mail-Einstellungen** Empfängeradressen eintragen
und zwischen zentralem und eigenem SMTP-Server wählen. Pro Benutzer sind bis zu
20 persönliche Empfänger vorgesehen; ohne persönliche Empfängerkonfiguration
gilt die Konto-E-Mail-Adresse als Standard.

Ein eigener SMTP-Zugang benötigt den passenden Host, Port, Benutzer, Passwort und
Absender. Das leere Passwortfeld behält bei einem vorhandenen Profil dessen
Passwort bei. Gespeicherte Zugangsdaten werden nicht zurückgegeben.

Für reguläre externe Server ist verifiziertes STARTTLS vorgesehen, üblicherweise
auf Port 587. Implizites TLS auf Port 465 wird nicht unterstützt. Die besondere
MailHog-Testkonfiguration ist davon getrennt.

### 13.2 Zentralen SMTP-Zugang einrichten

Administratoren beziehungsweise entsprechend berechtigte Konten verwenden
**Einstellungen → Zentrale SMTP-Einstellungen**.

1. Transport aktivieren und Host/Port, Absender und Zugangsdaten eintragen.
2. **Speichern und über n8n anwenden** wählen.
3. Den Auftrag über **Status aktualisieren** verfolgen.
4. Erst bei erfolgreicher Anwendung die weitere Versandkonfiguration prüfen.

Das Speichern erzeugt einen gesteuerten Konfigurationsauftrag. Die Bestätigung
der Anwendung ist kein Beleg einer bereits versendeten Testmail. Eine fehlerhafte
persönliche Route wechselt nicht automatisch auf zentrale Zugangsdaten.

### 13.3 Benachrichtigungspräferenzen und Versandregeln

Unter **Einstellungen → Benachrichtigungspräferenzen** persönliche Ereignisse,
Mindestpriorität, Versandform und Ruhezeiten konfigurieren. Berechtigte
Administratoren pflegen zusätzliche **Versandregeln** und **Vorlagen**.

Ein aktivierter SMTP-Zugang allein bedeutet noch keinen aktiven Versand für alle
Ereignisse. Auch Empfänger, Präferenzen, Regeln und Objektberechtigungen müssen
passen. Bei einer ausbleibenden Mail diese Ebenen getrennt prüfen.

### 13.4 Wochenberichte und Versandhistorie

Im Bereich der Benachrichtigungspräferenzen den **Wochenbericht automatisch
versenden** aktivieren, Wochentag, Uhrzeit und Zeitzone wählen und speichern.
Eine unmittelbar angebotene Berichtsanforderung erzeugt einen eigenen Auftrag;
Scan, Berichtserstellung und Mailzustellung können nacheinander ausstehen.

Die Berichtshistorie beziehungsweise Benachrichtigungsansichten unterscheiden
die jeweiligen Arbeits- und Zustellzustände. **In der Warteschlange** oder eine
Annahme durch das lokale Relay bedeutet nicht zwingend eine bestätigte Zustellung
beim Empfänger. Vor erneuter Anforderung vorhandene Historie und Fehler prüfen.

### 13.5 MailHog ausschließlich für Entwicklungstests

MailHog gehört nicht zum normalen Stack und ist nur im Entwicklungsmodus verfügbar:

```bash
./cve_mon mail-test start
./cve_mon mail-test status
./cve_mon mail-test logs
./cve_mon mail-test stop
```

Die Testoberfläche liegt auf `http://127.0.0.1:8025`. Für einen Test im Dashboard
`mailhog.cve.test` mit Port `1025` als Testtransport auswählen. Die Anwendung stellt
bestehende SMTP-Profile nicht automatisch um. Nach dem Test den gewünschten
regulären Transport wieder auswählen.

`mail-test stop` entfernt den Capture-Container und behält dessen Daten. Das
Stoppen des Testdienstes stellt keine SMTP-Einstellungen zurück. Keine echten
Zugangsdaten des Mailproviders als MailHog-Testzugang eintragen.

## 14. Benutzer und Rollen

### 14.1 Ein neues Konto einrichten

1. **Einstellungen → Benutzer** öffnen.
2. **Benutzer erstellen** wählen.
3. Benutzername, Anzeigename und E-Mail-Adresse eintragen.
4. Das Konto speichern und die Details prüfen.
5. Falls nötig zusätzliche Rollen bewusst zuweisen.
6. Die sichere Kontoaktivierung durch den Betreiber veranlassen.

Ein neues Konto erhält normalerweise `user`, aber kein voreingestelltes Passwort.
Die Erstellung allein ist noch keine abgeschlossene Aktivierung.

Der Betreiber kann einen zeitlich begrenzten Aktivierungsauftrag in eine neue
private Datei ausgeben:

```bash
.venv/bin/python scripts/security/issue-activation.py \
  --user-id BENUTZER_UUID \
  --output-file /private/kontoaktivierung.txt
```

Bei einer anderen Instanz `CVE_ENV_FILE` auf deren Konfiguration setzen. Den
Auftrag über einen geeigneten privaten Weg an die geprüfte Person übergeben.
Sie öffnet `/activate` auf der Dashboard-Domain, gibt den Aktivierungsauftrag im
Formular ein und setzt ein eigenes Passwort. Den Token nicht als URL-Parameter
weiterreichen. Eine automatische Aktivierungs-E-Mail wird durch diesen Ablauf
nicht vorausgesetzt.

### 14.2 Rollen und Objektfreigaben

Die Standardrolle `user` ist für den normalen Betrieb mit eigenen beziehungsweise
freigegebenen Beständen gedacht. `admin` ergänzt die administrativen Funktionen
und besitzt zugleich `user`. Benutzerdefinierte Rollen können die angebotenen
delegierbaren Berechtigungen bündeln; nicht jedes privilegierte Recht ist
weitergebbar.

Für fremde Server zusätzlich deren ACL prüfen. Ein neu zugewiesener Rollenname
macht nicht automatisch jeden fremden Server sichtbar. Bei einer Rechteänderung
kann eine erneute Anmeldung erforderlich werden.

### 14.3 Konto sperren, deaktivieren oder archivieren

Die Benutzerverwaltung bietet je nach Berechtigung Aktionen wie Aktivieren,
Deaktivieren, Sperren, Archivieren und Sitzungswiderruf. Vor einer Änderung das
richtige Zielkonto und die angezeigte Begründung prüfen. Das letzte nutzbare
Administratorkonto darf nicht versehentlich unbrauchbar gemacht werden.

MFA-Wiederherstellung und vollständiger Kontoverlust folgen dem vorgesehenen
Recoveryverfahren. Eine neue Administratorinitialisierung ist dafür kein Ersatz.
Für nachvollziehbare Änderungen stehen berechtigten Konten Auditinformationen
zur Verfügung.

## 15. Systemstatus und Fehlerdiagnose

### 15.1 Status richtig lesen

Unter **Systemstatus** sehen berechtigte Administratoren Dienste, Pipelines,
Beobachtungen und Vorfälle. Dabei unterscheiden:

| Ebene | Aussage |
|---|---|
| Container läuft | Der Containerprozess existiert |
| Bereitschaft | Der Dienst ist für seine vorgesehene Arbeit bereit |
| Fachliche Funktion | Relevante Schritte beziehungsweise Proben funktionieren |
| Aktualität | Inventar, CVE-Quelle oder Probe ist noch hinreichend frisch |
| Warteschlange | Es gibt wartende oder laufende Aufträge |

Ein grüner Container allein beweist keine aktuellen CVE-Daten und keine
abgeschlossene Verarbeitung. Ebenso kann ein alter Inventarstand eine Bewertung
überholt erscheinen lassen, obwohl alle Dienste erreichbar sind.

### 15.2 Einen Microservice gezielt neu starten

1. In der betreffenden Dienstzeile prüfen, ob eine Neustartaktion angeboten wird.
2. Den vorgesehenen Dienst auswählen beziehungsweise dessen Aktion öffnen.
3. Eine nachvollziehbare Begründung eintragen.
4. Den Neustart anfordern.
5. n8n-Freigabe, Ausführung und Ergebnis verfolgen.

Die Funktion startet einen freigegebenen Anwendungsprozess im bestehenden
Container neu. Sie ist kein allgemeiner Docker- oder Host-Neustart. n8n selbst
und Infrastrukturcontainer sind keine beliebigen Ziele dieser Funktion.
Ein wartender Auftrag wird bei ausgefallenem n8n nicht allein durch wiederholtes
Klicken ausführbar.

### 15.3 Informationen für eine Störungsmeldung

Notieren: Zeitpunkt, betroffener Server, konkrete Aktion, Fehlermeldung und
gegebenenfalls Submission-, Job-, Finding- oder n8n-Ausführungs-ID. Einen
reproduzierbaren Ablauf mit synthetischen Daten beschreiben. Keine Passwörter,
Tokens, privaten Schlüssel oder vollständigen produktiven Inventare in
öffentliche Issues übernehmen.

## 16. Betrieb mit cve_mon

### 16.1 Befehlsübersicht

| Befehl | Verwendung |
|---|---|
| `./cve_mon setup` | Lokale Python-Umgebung einrichten |
| `./cve_mon config` | Compose-Konfiguration ohne Ausgabe von Secrets prüfen |
| `./cve_mon check` | Alias für `config` |
| `./cve_mon build` | Dashboard und gemeinsames Anwendungsimage bauen |
| `./cve_mon start` | Kontrolliert starten beziehungsweise notwendige Aktualisierungen übernehmen |
| `./cve_mon up` | Alias für `start` |
| `./cve_mon status` | Containerstatus anzeigen |
| `./cve_mon ps` | Alias für `status` |
| `./cve_mon health` | Sieben Kerndienste, Datenbank und Hostcontroller prüfen |
| `./cve_mon logs` | Containerlogs lesen |
| `./cve_mon stop` | Stack und Hostcontroller stoppen; Daten behalten |
| `./cve_mon down` | Zusätzlich Container und Netze entfernen; persistente Daten behalten |
| `./cve_mon mail-test …` | Optionalen Entwicklungstestdienst verwalten |
| `./cve_mon reset --confirm PROJEKT` | Vollständiger Entwicklungsreset, siehe Abschnitt 19 |

Hilfe gibt es mit `./cve_mon --help` und beispielsweise `./cve_mon logs --help`.
`config` ist eine Konfigurationsprüfung und ersetzt keine laufende
Gesundheitsprüfung. `health` ist wiederum keine fachliche Schwachstellenabnahme.

### 16.2 Eine andere Instanzkonfiguration auswählen

Die globale Option steht vor dem Unterbefehl:

```bash
./cve_mon --env-file /etc/cve-monitor/server.env config
./cve_mon --env-file /etc/cve-monitor/server.env start
./cve_mon --env-file /etc/cve-monitor/server.env health
./cve_mon --env-file /etc/cve-monitor/server.env stop
```

Bei Bedarf zusätzlich `--sudo` verwenden. Projektname und Konfigurationsdatei
konsequent zusammenhalten. Ein abweichender Projektname wählt andere Ressourcen
und ist keine automatische Umbenennung einer vorhandenen Installation.

### 16.3 Logs lesen

```bash
./cve_mon logs --tail 100 api
./cve_mon logs -f processing
./cve_mon logs --tail 100 sources
./cve_mon logs --tail 100 n8n
./cve_mon logs --tail 100 postgres
./cve_mon logs --tail 100 postfix
# Nur bei aktiviertem Let’s Encrypt:
./cve_mon logs --tail 100 certbot
```

Die drei Anwendungsprofile sind `api`, `processing` und `sources`. `postfix` ist
ein Alias für das Mailrelay. Mit `-f` fortlaufend lesen; `Strg+C` beendet die
Loganzeige, nicht den Stack. Vor dem Weitergeben der Ausgabe deren Inhalt prüfen.

### 16.4 Start und Stop im Alltag

Ein wiederholtes `start` verwendet unveränderte passende Builds wieder. Bei
geänderten Quellen, Migrationen oder Konfigurationen kann ein kontrollierter
Rollout nötig sein. Gespeicherte Konten, Einstellungen und Bestände bleiben
bei einem regulären Start bestehen.

Für ein geplantes Wartungsfenster `stop` verwenden und anschließend `start` sowie
`health` ausführen. `down` ist kein Datenreset. Docker-Volumes, Bind-Verzeichnisse
oder Secrets nicht manuell löschen, um einen normalen Neustart zu erzwingen.

## 17. Sicherung und Wiederherstellung

### 17.1 Was zusammen gesichert werden muss

Eine vollständige Wiederherstellungsplanung umfasst mindestens:

- die Anwendungsdatenbank und die n8n-Datenbank;
- persistente n8n-Daten und den n8n-Verschlüsselungsschlüssel;
- projektbezogene Schlüssel, Rollenpasswörter und private Dienstkonfigurationen
  unter `SECRETS_BASE`;
- die zum Wiederherstellungsstand passende externe Konfiguration;
- Mailwarteschlange und weitere benötigte persistente Daten unter `MOUNT_BASE`;
- bei automatischer Ausstellung das ACME-Konto und Zertifikatsarchiv unter
  `MOUNT_BASE/acme/<projekt>/` sowie die private Cloudflare-Konfiguration;
- den passenden Repository-/Image-Stand und notwendige Zertifikatsabhängigkeiten.

Ein PostgreSQL-Dump allein ist keine vollständige Plattformwiederherstellung.
Ohne zugehörige Schlüssel können verschlüsselte Daten nach einem Restore
unbrauchbar sein.

### 17.2 Datenbankbackup und isolierter Restoretest

Für die konfigurierte Instanz kann der Betreiber ein neues geschütztes Ziel
verwenden:

```bash
CVE_ENV_FILE=.env make db-backup BACKUP_DIR=/private/backups/cve-db-001
CVE_ENV_FILE=.env make db-restore-test BACKUP_DIR=/private/backups/cve-db-001
```

Bei Serverbetrieb den Pfad hinter `CVE_ENV_FILE` entsprechend ersetzen.
Falls erforderlich `CVE_DOCKER_SUDO=1` ergänzen. Zielverzeichnisse nicht für
verschiedene Sicherungsstände wiederverwenden.

Der Datenbanktest stellt in einem eigenen isolierten Projekt wieder her und ist
keine Freigabe, eine laufende Produktivinstanz zu überschreiben. Zwei getrennte
Datenbankdumps sind zudem kein atomarer Gesamtstand über alle Anwendungskomponenten.
Bei laufenden Schreibern können sich die Daten zwischen einzelnen Schritten ändern.
[Umfang und Grenzen](operations/postgresql-backup-restore.md).

### 17.3 Vollständiger ruhender Sicherungsstand

Für eine dateibasierte vollständige Sicherung ein geplantes Wartungsfenster
verwenden:

1. Das richtige Projekt und seine Konfiguration feststellen.
2. Den Stack mit `./cve_mon stop` beziehungsweise der passenden `--env-file`
   stoppen.
3. Die diesem Projekt zugeordneten persistenten Daten, Secrets und Konfiguration
   mit der vorgesehenen Sicherungssoftware in einen neuen geschützten Stand sichern.
4. Dateieigentümer und Berechtigungen erhalten; benötigte Schlüssel gesondert
   geschützt verfügbar halten.
5. Den Stack wieder starten und `health` prüfen.
6. Die Wiederherstellbarkeit in einer dafür vorgesehenen isolierten Umgebung testen.

Nach `stop` ist auch PostgreSQL beendet. Ein Dumpbefehl benötigt dagegen eine
laufende Datenbank. Dumpverfahren und ruhende Dateisicherung deshalb nicht
unbesehen vermischen.

Ein produktiver Restore ist ein geplanter Wiederanlauf mit passendem Quellstand,
Daten und Schlüsseln. Das dokumentierte
[Release-/Recoveryverfahren](deployment/release-and-recovery.md) beschreibt die
entsprechenden Operatorwerkzeuge. Vor einem Cutover die Wiederherstellung prüfen;
keine einzelnen alten Schlüssel oder Tabellen nach Gefühl in eine laufende
Installation kopieren.

## 18. Wartung und Aktualisierung

Vor einer Änderung den aktuellen Quellstand, die Daten-/Secretpfade und einen
geprüften Sicherungsstand festhalten. Anschließend die vorgesehene Version im
Repository übernehmen und die dazugehörigen Prüfungen ausführen.

```bash
./cve_mon config
./cve_mon start
./cve_mon health
```

`start` übernimmt erforderliche Builds und Datenbankmigrationen kontrolliert.
Danach zusätzlich im Dashboard Anmeldung, Serverbestand, Inventaraktualität,
CVE-Datenstand und Verarbeitung prüfen. Ein erfolgreicher Containerstart allein
bestätigt noch nicht die gesamte fachliche Verarbeitung.

n8n-Definitionen werden im Repository gepflegt und bei jedem Containerstart
synchronisiert. Ein Imagewechsel muss zur getesteten Bootstrap-Version passen.
Herstellerimages und Abhängigkeiten sind festgelegt; deren Versionswechsel
koordiniert im Repository durchführen, nicht durch unabhängige automatische
Containerupdates.

Die alten Entwicklungspläne sind nur lokal archiviert und nicht Bestandteil des
GitHub-Imports. Für Installation und Prüfungen werden sie nicht benötigt.

## 19. Daten gezielt entfernen

### 19.1 Unterschiede der Aktionen

| Aktion | Auswirkung |
|---|---|
| Dashboardkonfiguration löschen | Entfernt das persönliche Layout, nicht den Serverbestand |
| Persönliche Gruppe löschen | Entfernt die Gruppe, nicht die zugehörigen Server |
| Server archivieren, soweit angeboten | Ändert den Lebenszyklus des Servers; ist keine vollständige Datenlöschung |
| Server endgültig löschen | Entfernt dessen Inventare, Findings, Historien, SSH-Zugangsdaten und abhängige Aufträge |
| `cve_mon down` | Entfernt Container/Netze und behält persistente Daten |
| `cve_mon reset` | Löscht die Daten des bestätigten Entwicklungsprojekts |

### 19.2 Einen Server endgültig löschen

1. Den Server anhand von Namen und Identität eindeutig bestimmen.
2. **Löschen** wählen, sofern das Konto dazu berechtigt ist.
3. Den angezeigten Löschumfang lesen.
4. **Server löschen** ausdrücklich bestätigen.
5. Den Abschluss beziehungsweise einen angezeigten Fehler kontrollieren.

Laufende Erfassungen und weitere Uploads für diesen Bestand werden gestoppt.
Inventare, Findings, Historien, Zugangsdaten und Aktualisierungsaufträge werden
entfernt. Die Anwendung verwirft auch ältere von ihr verwaltete Sicherungen,
die die gelöschten Serverdaten enthalten könnten. Das ist kein gewöhnliches
Archivieren und lässt sich in der Oberfläche nicht rückgängig machen.

Separat vom Betreiber angelegte externe Kopien oder bereits zugestellte E-Mails
liegen außerhalb dieser automatischen Bereinigung. Bei einer Störung des
Löschvorgangs den gemeldeten Zustand prüfen; nicht blind einen zweiten Vorgang
für vermeintlich dieselben Daten anlegen.

### 19.3 Vollständiger Entwicklungsreset

Nur für das bewusst ausgewählte Entwicklungsprojekt:

```bash
./cve_mon reset --confirm cve-monitoring-dev
./cve_mon start
./cve_mon health
```

Der Bestätigungswert muss exakt zum `COMPOSE_PROJECT_NAME` der gewählten
Konfiguration passen. Mit `--env-file` gegebenenfalls die richtige
Entwicklungsinstanz auswählen. Für Produktionsprojekte ist der Reset gesperrt.

Der Reset entfernt unter anderem Konten, Einstellungen, Inventare, CVE-/Finding-
Daten und n8n-Daten dieses Projekts. `.env`, bereitgestellte Eingangszertifikate
und Backups bleiben erhalten. Nach dem nächsten Start den ersten Administrator
neu einrichten. Einen Reset nicht als normale Fehlerbehandlung für einen
Versions- oder Verbindungsfehler verwenden.

## 20. Fehlerhilfe und Referenzen

### 20.1 Häufige Situationen

| Beobachtung | Prüfung und nächster Schritt |
|---|---|
| Dashboard nicht erreichbar | `config`, `status` und `health`; Bind-Adresse, Ports und Namensauflösung prüfen |
| TLS-Fehler oder unpassender Host | `DASHBOARD_DOMAIN`, Zertifikatsname, Kette und `TLS_DIR` prüfen; die richtige Dashboard-Adresse verwenden |
| Start meldet einen Unterprozessfehler | Die begrenzte Fehlerdiagnose lesen und Logs des betreffenden Dienstes prüfen |
| Login schlägt fehl | Kontoaktivierung, Benutzerstatus, Passwort und gegebenenfalls MFA prüfen; kein neues Bootstrapkonto als Umgehung anlegen |
| Ein Menü oder Server fehlt | Rolle und notwendige Serverfreigabe prüfen; ein direkter Link vergibt keine Rechte |
| Formular meldet Versionskonflikt | Aktuellen Stand laden und Änderung erneut fachlich prüfen |
| Inventar wurde geladen, erscheint aber nicht | Wurde tatsächlich **Server speichern** betätigt? Empfangsstatus und n8n-Verarbeitung prüfen |
| Scan bleibt deaktiviert | Rechte, Serverzustand und geeigneten vorhandenen Inventarstand prüfen |
| SSH-Auftrag wartet | Zentrale Steuerung und n8n-Freigabe prüfen, dann den Laufstatus auswerten |
| SSH-Anmeldung scheitert | Host/Port, Erreichbarkeit, beschränkten Benutzer, Credential und bestätigten Hostkey prüfen |
| Docker-Software fehlt | Docker-CLI, Syft, prlimit, beschränkten Socket und Leserechte am Ziel prüfen |
| Keine Findings sichtbar | Filter, Serverfreigabe, Inventarqualität, CVE-Datenstand und abgeschlossenen Abgleich prüfen; leere Liste ist allein keine Entwarnung |
| Mail kommt nicht an | Angewendetes SMTP-Profil, Empfänger, Präferenzen, Regeln, Berechtigungen und Versandhistorie getrennt prüfen |
| Mail bleibt nach einem Test aus | Prüfen, ob das Profil noch auf den inzwischen gestoppten MailHog zeigt |
| Neustartauftrag bleibt wartend | n8n und Hostcontroller prüfen; die Anforderung ist noch kein ausgeführter Neustart |
| Nach Restore keine Entschlüsselung | Zum Datenstand passende Schlüssel und private Konfiguration bereitstellen |

### 20.2 Weiterführende Dokumentation

| Thema | Anleitung |
|---|---|
| Installation und externe Konfiguration | [Umgebungen](deployment/environments.md) |
| Automatische Zertifikate | [Cloudflare DNS-01](deployment/letsencrypt-cloudflare.md) |
| Controller und Startverhalten | [Startcontroller](deployment/start-controller.md) |
| Automatische SSH-Erfassung | [Managed Ansible](operations/managed-ansible.md) |
| Lokale Playbooks und JSON-Erzeugung | [Ansible aus diesem Repository](../integrations/ansible/README.md) |
| Identitäten und Inventarübernahme | [Server-Onboarding](operations/server-onboarding.md) |
| Persönliche Dashboards | [YAML-Dashboards](dashboard/custom-dashboards.md) |
| Standardrollen | [admin und user](security/default-roles.md) |
| Mailkonfiguration | [SMTP](operations/smtp-configuration.md) |
| Prozessneustarts | [Microservice-Neustarts](operations/microservice-restarts.md) |
| Datensicherung | [PostgreSQL-Backup und Restoretest](operations/postgresql-backup-restore.md) |
| Fehler und Sicherheitsmeldungen | [Beitragsinformationen](../.github/CONTRIBUTING.md), [Sicherheitsmeldungen](../.github/SECURITY.md) |
| Lizenz | [Lizenzierungsmodell](legal/licensing.md) und [vollständiger Lizenztext](../LICENSE) |

Nichtkommerzielle Nutzung richtet sich nach PolyForm Noncommercial 1.0.0.
Kommerzielle Nutzung benötigt eine gesonderte Vereinbarung mit den zuständigen
Rechteinhabern. Diese Anleitung erteilt keine zusätzliche kommerzielle Lizenz.
