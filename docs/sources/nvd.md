# NVD API 2.0

Register-ID: `nvd`. Offizielle Grundlage: [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).

Endpunkt services.nvd.nist.gov/rest/json/cves/2.0. Initial/reconcile durchläuft
Publikationsfenster ab 1970 bis zum festen Run-Zeitpunkt; jedes Fenster ist höchstens
120 Tage lang. Incremental nutzt lastModStartDate/lastModEndDate und standardmäßig
24 Stunden Überlappung ab dem letzten erfolgreichen Watermark. Pro Fenster vollständige
Pagination über startIndex/resultsPerPage, maximal 2000 Records. Offset, Anzahl und
Gesamtmenge müssen konsistent bleiben; fehlende/geänderte Seiten ergeben keinen Erfolgscursor.

Ohne API-Key mindestens 6,1 Sekunden Request-Abstand (5/30 Sekunden); mit Key mindestens
0,65 Sekunden (50/30 Sekunden), konservativer Standard 6,5 Sekunden. Der Abstand wird in
PostgreSQL reserviert und bleibt über Neustarts wirksam. Retry-After wird berücksichtigt.
Optionaler Key nur aus privater Datei und ausschließlich im apiKey-Header an NVD.

Vollständiges originales cve-Objekt einschließlich Beschreibungen, Referenzen, CVSS,
Configurations und CPE-Kriterien. Externe ID ist cve.id. Naive ISO-API-Zeitstempel werden
nur für NVD als UTC akzeptiert; Originaltext bleibt unverändert. Rejected wird historisiert.
Das gepinnte NVD-JSON-Schema mit sämtlichen lokalen CVSS-/SSVC-Abhängigkeiten wird offline
aufgelöst. Einzelrecordfehler erlauben die Persistenz gültiger Nachbarn, verhindern aber
den vollständigen Laufstatus.

Transport-, Größen- und Retrygrenzen: [Sicherheit](../security/cve-importer-security.md).
Betrieb: [Importer](../operations/cve-importer.md).
