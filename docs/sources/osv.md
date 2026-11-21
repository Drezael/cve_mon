# OSV

Register-ID: `osv`. Offizielle Grundlage: [OSV](https://google.github.io/osv.dev/data/).

Pro explizit freigegebenem Ökosystem storage.googleapis.com/osv-vulnerabilities/
<ecosystem>/all.zip für initial/reconcile. Es gibt keinen stillschweigenden globalen Import;
osv_ecosystems ist standardmäßig leer. Die geschlossene Liste im Konfigurationsmodell kann
nur durch ein geprüftes Codeupdate erweitert werden. Ökosystemnamen werden URL-kodiert.

Incremental liest <ecosystem>/modified_id.csv (timestamp,id, absteigend) und die passenden
<id>.json-Records mit 24 Stunden Überlappung. Reihenfolge, Zeitstempel, Identität und
Einzelrecord-Dateiname werden geprüft. Fortschritt ist pro Indexposition/Ökosystem dauerhaft;
Erfolgscursor wird erst nach allen gewählten Ökosystemen geschrieben.

OSV-Schema 1.0 bis 1.7 mit Patchversionen, vollständige affected-Ranges/Events/Versions,
Aliases, related, database_specific und ecosystem_specific gemäß Originalschema.
Withdrawn wird als eigene Revision gespeichert. Aliase können mehrere oder keine CVEs
enthalten. Advisory-ID bleibt die Identität; sie wird nicht durch eine CVE-ID ersetzt.
Jeder inkrementelle Einzelrecord erhält sein tatsächliches Downloadartefakt und seinen
Originalbyte-SHA, zusätzlich zum separaten JSONB-Inhalts-SHA.

Transport-, Größen- und Retrygrenzen: [Sicherheit](../security/cve-importer-security.md).
Betrieb: [Importer](../operations/cve-importer.md).
