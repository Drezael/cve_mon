# CVEProject / cvelistV5

Register-ID: `cve_list`. Offizielle Grundlage: [CVEProject / cvelistV5](https://github.com/CVEProject/cvelistV5/blob/main/README.md).

Standardquelle ist ausschließlich `https://github.com/CVEProject/cvelistV5.git`, Branch `main`.
Die private persistente Arbeitskopie liegt unter dem Importer-Scratch-Verzeichnis in
`git/cvelistV5`. Der erste Abruf verwendet einen flachen Clone ohne Tags. Updates erfolgen
mit `git pull --ff-only --no-rebase --no-tags origin main` über den vorhandenen HTTPS-Egress.
SSH, Dateitransport, interaktive Credentials, Hooks und rekursive Submodule sind deaktiviert.

Der erste Import liest alle regulären `cves/<Jahr>/<Bereich>/CVE-*.json`-Dateien. Spätere
inkrementelle Läufe vergleichen den letzten erfolgreich importierten Commit mit dem neuen
HEAD. Nur hinzugefügte, geänderte und gelöschte CVE-Dateien werden verarbeitet; Änderungen
an README, Deltalogs oder anderen Metadaten lösen keine CVE-Verarbeitung aus. Ein identischer
Stand erzeugt keine Aufbereitungsjobs. Entfernte Dateien erhalten `present=false` und werden
neu bewertet; vorhandene Revisionen und ihre Provenienz bleiben nachvollziehbar.

Commit, Dateimanifest und Seitenposition werden vor beziehungsweise während des Imports
gefencet gespeichert. Ein Wiederanlauf setzt denselben Commit an der letzten bestätigten
Position fort, ohne währenddessen einen neueren Upstreamstand einzumischen. Erst ein
vollständig erfolgreicher Lauf setzt den Erfolgs-Cursor weiter. Nach einem vollständigen
Scan mit einzelnen Validierungsfehlern dient der gescannte Commit dennoch als Diff-Basis;
zusätzlich werden ausschließlich die dokumentierten Fehlerdateien erneut geprüft.
Unveränderte valide Records werden nicht erneut gelesen. `partial` bleibt bis zum
fehlerfreien Nachlauf sichtbar; ein abgebrochener, unvollständiger Scan wird nicht als
neue Diff-Basis verwendet. Dateien
werden gegen ihre Git-Blob-ID geprüft. Zwei begrenzte Parserprozesse validieren Pakete
parallel. Die anschließende Aufbereitung arbeitet mit gebündelten Jobs und einem Batch-Writer.

Der bisherige Release-Adapter bleibt für ausdrücklich konfigurierte Bestands-/Testumgebungen
über `cve_list_transport="release"` verfügbar. Im Standard und im lokalen Produktivlauf
wird er nicht verwendet. NVD, OSV, Ubuntu, separater KEV-Feed und EPSS sind standardmäßig
deaktiviert; sie werden nur bei ausdrücklicher abweichender Konfiguration eingeplant.

Formate 5.0, 5.1 (auch 5.1.0), 5.1.1 und 5.2 (auch 5.2.0) werden gegen gepinnte Originalschemas geprüft.
Die 5.1-Familie verwendet das kompatible Original-Patchschema 5.1.1: Im offiziellen
Repository gibt es als 5.1 deklarierte Records mit gültigem `cpeApplicability`.
Deklarierte Version und Originaldaten bleiben unverändert; unbekannte Versionen und
schemawidrige Werte werden weiterhin abgewiesen.
PUBLISHED/REJECTED, CNA-, Program-/ADP-Container bleiben erhalten. CVE-ID ist die externe
Quellenidentität. Die unterstützten Schema-Commits und alle Abhängigkeiten stehen im
vendorten data/schemas.json. Unbekannte Versionen werden abgewiesen.

Transport-, Größen- und Retrygrenzen: [Sicherheit](../security/cve-importer-security.md).
Betrieb: [Importer](../operations/cve-importer.md).

## Gepinnte Upstream-Besonderheit

Die CVSS-3.1-Abhängigkeit der CVE-Schemas 5.1/5.1.1/5.2.0 enthält den JSON-Schlüssel
scoreType zweimal (zuerst Bereich, zuletzt eine strengere Zehntelwert-Enumeration).
Die unveränderten Originaldateien werden mit der letzten Definition ausgewertet. Der
Repositoryvalidator erlaubt diese Besonderheit ausschließlich für genau diese drei Pfade
und den gepinnten SHA-256 9b0a73323ad9821390af2a446572bee9169f861db073b64cc820b0b49ea2fd29.
Alle Quellrecords und sonstigen JSON-Dateien lehnen doppelte Schlüssel weiterhin ab.
