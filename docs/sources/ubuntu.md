# Ubuntu Security API

Register-ID: `ubuntu`. Offizielle Grundlage: [Ubuntu Security API](https://ubuntu.com/security/api/docs).

Endpunkte ubuntu.com/security/cves.json und /security/notices.json. Die tatsächlichen
Canonical-Parameter stammen aus webapp/schemas.py und webapp/views.py des offiziellen
ubuntu-com-security-api-Repositories. Limit maximal 20, Offset und total_results werden
kontrolliert. CVEs werden in drei unabhängigen Statusströmen active, not-in-ubuntu und rejected
mit sort_by=updated, order=descending gelesen. Inkrementell wird bis zum überlappenden
Wasserstand gelesen; Reihenfolge und Zeitangaben werden geprüft. Notices haben keinen
supported modified-since-Filter und werden mit order=newest vollständig abgeglichen.

Keine erfundenen modified_since-Parameter. CVEs, USN/LSN/SSN-Advisories, cves_ids und
verschachtelte CVE-Referenzen bleiben eigenständige Identitäten. Releases, Paketstatus,
Quellpakete und vollständige Epoch/Version/Release-Werte bleiben im Original-JSONB.
Ein Notice muss keine einzelne CVE repräsentieren.

Das lokale Ubuntu-JSON-Schema ist ein bewusst enger, selbst verfasster Consumer-Vertrag
auf Basis der öffentlichen Canonical-Marshmallow-Definitionen, kein angeblich offizielles
Upstream-JSON-Schema. Es erlaubt zusätzliche originale Quellfelder. API-/Schemaänderungen
müssen als Vertragsupdate geprüft werden. Die vollständige API-Spezifikation war während
der Recherche zeitweise nicht erreichbar; die offizielle Implementierung wurde lesend geprüft.
Quelle: https://github.com/canonical/ubuntu-com-security-api.

Transport-, Größen- und Retrygrenzen: [Sicherheit](../security/cve-importer-security.md).
Betrieb: [Importer](../operations/cve-importer.md).
