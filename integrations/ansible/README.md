# Ansible aus diesem Repository

Die automatische Erfassung benötigt keinen externen Ansible-Checkout. Sämtliche
Playbooks und Collector-Helfer werden hier versioniert und mit dem gemeinsamen
Anwendungsimage ausgeliefert:

| Datei | Aufgabe |
|---|---|
| [collect.yml](../../services/automation/src/cve_automation/playbooks/collect.yml) | System, Pakete, Dienste und vorhandene Docker-Software lesen |
| [connection-test.yml](../../services/automation/src/cve_automation/playbooks/connection-test.yml) | SSH-Verbindung und unprivilegierte UID prüfen |
| [execute.py](../../services/automation/src/cve_automation/execute.py) | Bestätigten Hostkey erzwingen, festes Playbook mit Ansible Runner ausführen |
| [Host-/Docker-Helfer](../../services/automation/src/cve_automation/data/host_identity.py.txt) | Lesende Python-Helfer für Hostidentität, Docker-Metadaten und SBOMs |

Die YAML-Dateien sind die einzigen Playbook-Quellen: Die Paketkonfiguration nimmt
sie direkt auf, es gibt keine zweite Kopie im Integrationsverzeichnis. Der
Verbindungstest wird ebenfalls aus YAML geladen und nicht in Python erzeugt.
Hostkey-Abfragen erfolgen mit `ssh-keyscan` ohne Anmeldung und benötigen kein Playbook.

Im normalen Betrieb die Verbindung im Dashboard einrichten und den gelesenen
Hostkey am Zielsystem prüfen und bestätigen. n8n gibt Tests und Erfassungen frei;
der Quellen-/SSH-Container startet ausschließlich diese festen Playbooks.

## Rechte und Voraussetzungen

Ein eigener Zielbenutzer mit beschränkten Rechten und SSH-Schlüssel ist empfohlen.
Keine Root-Anmeldung, keine sudo-Rechte und kein Zugriff auf den normalen Docker-Socket.
Die Erfassung verändert keine Systemkonfiguration, Pakete, Dienste oder Container
und installiert keine Hilfswerkzeuge. Private temporäre Arbeitsdateien sind möglich.

Auf dem Zielhost sind SSH-Server und Python 3 erforderlich, für Paketfakten
gegebenenfalls `python3-apt` beziehungsweise `python3-rpm`. Für Docker-Analysen
müssen ein Administrator Docker-CLI, `/usr/bin/prlimit`, Syft unter
`/usr/local/bin/syft` und den beschränkten Docker-Leseendpunkt
`/run/cve-monitoring/docker-readonly.sock` bereitstellen.
[Vollständige Vorgaben](../../docs/operations/managed-ansible.md).

## Lokale Inventardatei erzeugen

Das lokale Werkzeug verwendet dieselben gepackten Playbooks wie der Container.
Zuerst `./cve_mon setup` ausführen. Eine private Verbindungskonfiguration nach
[ansible-target.json](../../configuration/examples/ansible-target.json) anlegen;
Konfiguration und private Schlüssel-/Passwortdateien müssen dem ausführenden
Benutzer gehören und Modus 0600 haben. Absolute Credential-Pfade verwenden.

```sh
chmod 600 /private/target.json /private/cve-inventory.key
.venv/bin/python -m scripts.ansible.manage probe --config /private/target.json
# Ausgegebenen öffentlichen Hostkey am Ziel prüfen und in target.json bestätigen.
.venv/bin/python -m scripts.ansible.manage test --config /private/target.json
.venv/bin/python -m scripts.ansible.manage collect --config /private/target.json --output /private/inventory.json
```

Die Erfassung schreibt ausschließlich die lokale Inventardatei auf dem Controller
mit Modus 0600 und entfernt ihre temporären Arbeitsdateien. Danach kann die Datei
im Dashboard hochgeladen werden. Bei Passwortanmeldung `auth_method=password` und
`password_file` verwenden; eine Schlüssel-Passphrase kann über `passphrase_file`
bereitgestellt werden. Geheimnisse gehören weder in Kommandozeilen noch ins Repo.
Alle Zieladressen und Netze sind zulässig; der SSH-Hostkey bleibt verbindlich.

Die optionale interne Collector-Bridge verwendet ebenfalls diesen Collector.
Ihr HTTPS-Submit-Client liegt unter `scripts/ansible/submit.py` und benötigt einen
explizit eingerichteten privaten mTLS-Inventarendpunkt. Er öffnet keine Ports und
macht die technische API nicht öffentlich zugänglich. Im normalen Stack werden
Inventare intern übernommen oder über das Dashboard hochgeladen; ein separates
Submit-Playbook auf dem Zielhost ist dafür nicht erforderlich.

## Prüfungen

```sh
make inventory-collect-syntax
make inventory-collect-test
make inventory-collect-integration
make inventory-submit-test
```

Die Integrationsprüfung startet eigene kurzlebige SSH-Testcontainer und prüft auch
die im gebauten Anwendungsimage enthaltenen Playbooks. Sie inventarisiert keine
konfigurierten Produktivserver. Alle Prüfziele verwenden die lokale `.venv` und
Dateien aus diesem Checkout.
