# ADR-0038: Externe Konfiguration und feste interne Architektur

Status: angenommen, 21.11.2026.

Die `.env` beschreibt ausschließlich die Umgebung außerhalb der Anwendung:
Betriebsmodus, Projektname, Hostverzeichnisse, Dashboard-Domain und veröffentlichte
Ports, externe Zertifikate beziehungsweise Cloudflare-DNS-Zugang, ACME-Kontakt
und Zustimmung sowie die externe SMTP-Anbindung. SSH-Ziele werden pro Server im Dashboard hinterlegt.
Interne Dienstadressen, Datenbankrollen, Containerports, Pool-/Workerzahlen,
Heartbeats, Leases und Sicherheitsbudgets sind keine Konfigurationsoptionen.

Die öffentliche Schlüsselliste steht in `scripts/infrastructure/policy.py`.
Interne Werte sind dort unveränderliche, versionierte Vorgaben und in `compose.yml`
als feste Containerwerte eingetragen. Der Loader weist interne `.env`-Einträge und
programmatische Überschreibungen ab; gleichnamige Shellvariablen haben keine Wirkung.
Die Modellvalidierung vergleicht interne Containerwerte mit dem Architekturvertrag.
Änderungen erfordern Code-/Compose-Änderungen und Tests. Host-UID/GID werden vom
Controller abgeleitet, die Datenbank-Secretablage aus `SECRETS_BASE`.

Extern wird ausschließlich Nginx für das Dashboard veröffentlicht. Login und die
benötigte Dashboard-API laufen über dieselbe Domain. Separate öffentliche API-,
Inventar- oder n8n-VHosts sind nicht aktiv. PostgreSQL, Verarbeitung, Quellen, n8n
und Mailrelay haben keine Hostports. Ihre Topologie und Zugänge sind intern.

`TLS_DIR` bezeichnet bei deaktiviertem Certbot-Dienst den externen Certbot-Live-Ordner mit `fullchain.pem` und `privkey.pem`.
Certbot-Symlinks nach `archive/` bleiben gültig. Dienste erhalten nur minimale
read-only TLS-Snapshots unter `SECRETS_BASE`. Der Hostcontroller prüft Erneuerungen
alle 60 Sekunden und lädt Nginx nach Prüfung neu. Bei ungültigen Dateien bleibt das
bisherige Zertifikat aktiv. Interne Schlüssel und Zertifikate werden von der
Dienstvorbereitung erzeugt und unverändert wiederverwendet.

MailHog gehört zum optionalen `infrastructure/compose/mail-test.yml`-Profil `mail-test`. Es ist
kein Bestandteil des normalen Starts, Healthchecks oder Releaseinventars.
`cve_mon mail-test start/stop` verwaltet es ausdrücklich für Mailtests; seine
Oberfläche bleibt an Loopback gebunden. Normale SMTP-Einstellungen enthalten keine
implizite MailHog-Abhängigkeit.

Isolierte Tests dürfen im Testcode synthetische Config-/Compose-Fixtures erzeugen.
Das erweitert nicht die akzeptierte `.env`-Schnittstelle; exportierte Umgebungsdateien
enthalten ausschließlich die öffentliche externe Konfiguration.

Die integrierte SSH-Inventarisierung schränkt Zieladressen nicht nach Netzen ein.
Eine externe Netz-Allowlist entfällt. Die Namespace-Firewall erlaubt konkrete aktive
SSH-Ziele; sie unterstützt IPv4 und IPv6. Das feste Playbook führt keine
Systemänderungen aus und installiert keine Werkzeuge. sudo und Root-Anmeldung sind
ausgeschlossen. Docker wird nur über den administrativ beschränkten lokalen
Leseendpunkt `/run/cve-monitoring/docker-readonly.sock` angesprochen. Werkzeuge
werden auf Zielhosts vorab installiert; nur private temporäre Arbeitsdateien sind
für die Erfassung erforderlich.

Der n8n-Container synchronisiert und veröffentlicht seine versionsverwalteten
Workflows bei jedem eigenen Start vor dem Serverstart. Definitionen und Bootstrap
werden read-only aus dem Repository eingebunden, die verwalteten Credentials aus
der privaten Dienstkonfiguration. Ein CLI-Initialisierungsargument entfällt.
Dies gilt auch bei Docker-Restarts. Anwendungszeitpläne und Pause-Einstellungen
bleiben erhalten; fremde IDs werden nicht gelöscht. Ein Bootstrapfehler verhindert
den n8n-Serverstart.

Die Ansible-Playbooks liegen vollständig im Repository unter
`services/automation/src/cve_automation/playbooks/` und werden als Paketdaten des
SSH-Executors ausgeliefert. Erfassung und Verbindungstest verwenden diese festen
YAML-Dateien. Lokale Collectoren und Prüfziele verwenden denselben Quellstand;
ein externer Ansible-Checkout, dessen Launcher oder dessen virtuelle Umgebung
sind keine Abhängigkeit.

Der optionale Certbot-Dienst verwendet ausschließlich DNS-01 mit dem Cloudflare-Plugin.
Er darf weder HTTP-/Standalone-Challenges noch einen HTTP-Fallback ausführen.
Aktivierung, Kontaktadresse, Zustimmung und DNS-API-Token sind externe Eingaben;
Plugin, CA-Adresse, Zertifikatsname, Containerpfade und Zeitbudgets bleiben im Code.
Das Originalimage wird unveränderlich gepinnt. ACME-Zustand und Zertifikate liegen
unter `MOUNT_BASE/acme/<projekt>/`, die private Credentialdatei unter
`SECRETS_BASE/acme-credentials/<projekt>/`. Der Container erhält ausschließlich
Ausgangsnetzwerk, keine Hostports und keinen Docker-Socket. Interne TLS-Identitäten
bleiben von der öffentlichen Dashboard-Domain getrennt. Weitere DNS-Provider
benötigen eine versionierte Implementierung und eigene Prüfungen.
