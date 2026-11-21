# Docker-Software inventarisieren und überwachen

Inventarversion 1.3 ergänzt die bestehenden Hostinformationen um `container_software`.
Versionen 1.0 bis 1.2 bleiben gültig. Alte Inventare ohne Softwarelisten erscheinen
als **nicht erfasst**, niemals als geprüfte Container ohne Schwachstellen.

## Erfassung auf dem Docker-Host

Der Ansible-Collector erfasst weiterhin Container-ID, Image-ID und Zustand. Syft
untersucht das tatsächlich lokale Image im zusammengeführten Zustand. Es erfolgt
kein Pull eines möglicherweise inzwischen veränderten Tags. Die Images und ihre
Container werden nicht umgebaut. Es gibt keine Softwareinstallation oder
Ausführung von Abfrageprogrammen innerhalb überwachter Container.

Die Referenzversion von Syft und die SHA256-Werte für Linux amd64/arm64 stehen in
`scripts/container_inventory/syft.lock.json`. Ein Administrator installiert Syft
vorab unter `/usr/local/bin/syft` auf dem Zielhost. Die Erfassung kopiert keine
Werkzeuge und installiert keine Pakete. Für Docker wird ausschließlich der
administrativ beschränkte Endpunkt `/run/cve-monitoring/docker-readonly.sock`
verwendet; die normale Docker-Gruppe ist kein beschränkter Lesezugang.

Der Collector verarbeitet SBOMs und Exporte in privaten temporären Verzeichnissen,
die nach dem Lauf entfernt werden. Es werden keine dauerhaften SBOM-Caches auf
dem Zielhost neu angelegt. Fehlende Rechte oder Werkzeuge werden als fehlende
beziehungsweise fehlgeschlagene Softwareerfassung ausgewiesen.

Änderungen in der beschreibbaren Schicht
werden mit `docker diff` erkannt. Anschließend wird das aktuelle Root-Dateisystem
exportiert und statisch untersucht. Ein vollständiger Laufzeitstand ersetzt für
die Bewertung den Image-Stand, sodass entfernte Pakete nicht weiter als installiert
gelten. Archive werden begrenzt verarbeitet; absolute Pfade, Parent-Traversal,
Gerätedateien und Links werden nicht extrahiert. Die Erfassung ist keine atomare
Momentaufnahme einer schreibenden Anwendung.

Docker-Exporte enthalten keine Volumes. Anwendungspfade daher ausdrücklich pro Host
konfigurieren, beispielsweise:

```yaml
inventory_container_application_mounts:
  - /opt/application
  - /var/www/html
```

Die Pfade sind Ziele **im Container**. Nur zugehörige Docker-Mounts werden auf dem
Host gelesen. Datenbank-, Backup- und Nutzdatenverzeichnisse gehören nicht in diese
Liste. Imagepakete, deren Fundstellen vollständig von einem erfassten Mount
überdeckt werden, werden für diesen Container nicht als aktive Imagepakete bewertet.
Nicht konfigurierte Mounts sind außerhalb des Erfassungsumfangs.

Syft erkennt Paketdatenbanken und unterstützte Anwendungsmetadaten. Eigenständige
Binärdateien ohne Versionsinformationen können unzuordenbar bleiben. Eine SBOM ist
kein Nachweis, dass ein Paket aktuell als Prozess läuft. Es werden installierte
Komponenten laufender Container überwacht. Gestoppte Container bleiben im Inventar,
erzeugen aber keine aktiven Softwarebewertungen.

Übertragen wird eine erlaubte Projektion von Softwarefakten (Paket, Version, Typ,
PURL, Fundstellen, Distribution). Docker-Umgebungsvariablen, Startbefehle, Zugangsdaten
und Dateiinhalte werden nicht in den Monitor hochgeladen. Identische Dokumente
werden in PostgreSQL anhand ihres Inhalts einmal gespeichert und mit Snapshots
sowie Containern verknüpft. Maximal zwei Container werden parallel verarbeitet.

## Zentrale Steuerung über n8n

Der Workflow `cve-control-inventory` gibt regelmäßige und manuelle Erfassungsaufträge
frei. Die integrierte Erfassung läuft im vorhandenen Quellen-/SSH-Container, mit
festen, im Repository versionierten Playbooks und ohne zusätzlichen Container.
Verbindungen und Intervalle werden in der Serververwaltung gepflegt. Der normale
Stack besteht aus sieben Kerndiensten; MailHog ist ausschließlich optional für Tests.

Playbooks:
[`collect.yml`](../../services/automation/src/cve_automation/playbooks/collect.yml) und
[`connection-test.yml`](../../services/automation/src/cve_automation/playbooks/connection-test.yml).
Die Python-Helfer liegen daneben im Paket `cve_automation/data`; beim Imagebau
werden YAML und Helfer gemeinsam gepackt. Es besteht keine Abhängigkeit von einem
externen Ansible-Checkout oder dessen Vault-/Launcher-Strukturen.

Für eine separat gewünschte, ausgehend verbindende interne Collector-Bridge gibt es
`scripts/container_inventory/runner.py`. Sie verwendet dieselbe lokale Erfassung
und den lokalen HTTPS-Client aus `scripts/ansible/`. Eine private Konfiguration
verbindet jeden Alias mit einer `connection_file`, siehe
[`container-collector.json`](../../configuration/examples/container-collector.json).
Sie benötigt einen ausdrücklich eingerichteten internen technischen mTLS-Endpunkt;
der normale Dashboard-Gateway veröffentlicht diese Endpunkte nicht.

```sh
.venv/bin/python -m scripts.container_inventory.runner --config /private/collector.json --register --once
.venv/bin/python -m scripts.container_inventory.runner --config /private/collector.json
```

n8n bestimmt die Fälligkeit, die Bridge fragt freigegebene Aufträge ab und meldet die
zugehörige Submission zurück. Sie übernimmt keine frei wählbaren Befehle vom
Monitor. Die [Systemdienstvorlage](../../configuration/examples/cve-inventory-collector.service)
verwendet ausschließlich diesen Checkout. Für den normalen Betrieb genügt die
integrierte SSH-Erfassung oder der JSON-Datei-Upload im Dashboard.

## CVE-Abgleich und Anzeige

Die bestehende CVE-v5-Quelle bleibt die einzige Schwachstellenquelle. Syft erzeugt
Softwareinventare und verwendet keine weitere Schwachstellendatenbank.

Neue Inventare berücksichtigen den gesamten aktuellen CVE-Index. CVE-Updates
bewerten nur neue/geänderte/entfernte CVEs gegen die gespeicherten Host- und
Containerkomponenten aller berechtigten Server. Sie lösen keinen erneuten Syft-Scan
aus. Distribution und Version des Containers werden getrennt vom Host verwendet.
Nicht eindeutig zuordenbare Produkte und Versionsschemata bleiben unsichere Hinweise.

In den Serverdetails stehen Container, Zustand, Paketzahlen pro Herkunft, letzter
Erfassungszeitpunkt und Fehlerstatus. Die Paketliste ist paginiert. Findings zeigen
den Container und die betroffene Software mit installierter Version und Herkunft.
Ein Server/CVE-Finding kann mehrere Containerkomponenten als Belege enthalten;
diese Komponenten werden nicht als zusätzliche Findings gezählt.

## Prüfung

- Unit-Tests: unterschiedliche Distributionen, gestoppte Container, Laufzeitersetzung,
  überschattende Mounts und Projektion ohne Docker-Konfiguration.
- Native Tests: Inventarannahme 1.3, unveränderter Originalinhalt, deduplizierte SBOMs,
  Erst- und CVE-seitiger Abgleich sowie ACL-geschützte Lesezugriffe.
- Reales Docker/Syft: anfälliges Imagepaket, im Testcontainer aktualisierte Version und
  zusätzlich eingebundene Anwendung. Nur kurzlebige Testressourcen werden verändert.
- Reales n8n: Freigabe eines Erfassungsauftrags, technische Lease und anschließende
  Verarbeitung eines hochgeladenen Containerinventars.
