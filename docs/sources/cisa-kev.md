# CISA Known Exploited Vulnerabilities

Register-ID: `cisa_kev`. Offizielle Grundlage: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

Vollständiger JSON-Katalog unter www.cisa.gov/sites/default/files/feeds/
known_exploited_vulnerabilities.json. Alle Modi laden den gesamten Katalog. Schema,
catalogVersion, dateReleased, count, eindeutige CVE-IDs und tatsächliche Eintragszahl
werden vor Erfolg geprüft.

Ein eigener Record `catalog` bewahrt den vollständigen Katalog und seine Metadaten;
zusätzlich erhält jeder Eintrag einen Record mit cveID. Änderungen der Fristen, Ransomware-
Einordnung, CWEs und Beschreibungen erzeugen neue unveränderliche Revisionen.
Nur ein vollständig akzeptierter Katalog kann fehlende bisherige Mitglieder als abwesend
markieren; History und Rohrevisionen bleiben erhalten. Standard-Mindestquote 0,5 schützt
vor unbeabsichtigten Massenentfernungen. Ein unvollständiger oder regressiver Katalog
ändert keinen Erfolgscursor und entfernt keine bisherigen Einträge.

V5-Git und KEV können denselben Importer verwenden. Der private Unterordner `git`
enthält das persistente Repository und gehört nicht zum HTTP-Artefaktcache; die
Downloadquota zählt die Artefakte in den jeweiligen Laufverzeichnissen. Symlinks
oder fremde beziehungsweise öffentlich zugängliche Git-Cacheverzeichnisse werden
weiterhin abgewiesen.

Transport-, Größen- und Retrygrenzen: [Sicherheit](../security/cve-importer-security.md).
Betrieb: [Importer](../operations/cve-importer.md).
