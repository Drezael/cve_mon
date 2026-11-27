# Lieferkette und SBOM Phase 23

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Trivy 0.76.2 wird lokal unter .runtime/hardening/tools installiert. SHA256 der offiziellen Linux-64bit-Distribution: bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf. Sowohl Download als auch installierte Binärbytes werden vor jedem Scan geprüft. Installation: make security-tools. Kein Scanner erhält einen Docker-Socketmount; der Operator exportiert Kandidatenimages über die vorhandene Docker-CLI, anschließend scannt Trivy ausschließlich das Archiv.

make security-dependencies scannt Runtime-, Entwicklungs- und npm-Lockgraph inklusive Development-Abhängigkeiten getrennt und erzeugt CycloneDX-SBOMs. make security-images löst alle sieben physischen Composeartefakte auf unveränderliche Image-IDs auf, erzeugt jeweils Rohreport/SBOM und ein Imageinventar. Abbrüche, fehlende Paketinventare und unbekannte Scannerschwere ergeben keinen erfolgreichen Gate. HIGH/CRITICAL/UNKNOWN blockieren auch ohne verfügbaren Fix. Neue Funde werden niemals automatisch ausgenommen. Einzelbewertungen stehen in
[image-reviews.json](../../infrastructure/image-reviews.json): exakte Image-Digests,
CVE/Regel-ID, Paket, installierte Version, Schweregrad und betroffener Scanbereich,
Begründung, geprüfte Quelldateien und Ablaufdatum. Geänderte Konfigurationshashes,
abgelaufene Bewertungen oder neue Funde lassen das Gate scheitern. Der Gatebericht
führt jede angenommene Bewertung ausdrücklich unter `exceptions` auf.

make phase-23-acceptance prüft konkrete Berichte und gibt bei fehlenden Nachweisen oder offenen Imagebefunden NO_GO zurück. Lokale Provenienz enthält Quellhashes, Scannerhash und Inventar, keine Secrets/Env-Werte. Sie ist keine signierte SLSA-Attestation. Scanner-DB-Datum und genaue Artefaktversion bleiben Teil der Rohreports; ein Scan ist zeitgebunden und keine Zertifizierung. Runtime-/Devlocks und gepinnte CI-Actions bleiben erhalten. Es erfolgt kein Registry-Push.

Grundlagen: [Trivy Vulnerability Scanning](https://trivy.dev/docs/v0.76/guide/scanner/vulnerability/) und [SBOM](https://trivy.dev/docs/v0.76/guide/target/sbom/).

Die Dependencyprüfung umfasst vier eigene Graphen: Runtime, Entwicklung, Frontend und Python-Buildwerkzeuge. n8n wird ausschließlich als unverändertes Herstellerimage geprüft; ein lokaler npm-Overridegraph existiert nicht mehr. Das gemeinsame Anwendungsimage installiert hashgesperrte Wheels auf dem unveränderten offiziellen Python-Image. [Original-Images und Aktualisierung](../deployment/upstream-images.md).

OS-Scanner können eingebettete Bibliotheken oder verzögerte Distributionsmeldungen übersehen. Deshalb erfasst `scripts/hardening/components.py` zusätzlich die tatsächlichen SQLite-/Expat-/OpenSSL-/Node-Versionen und den unveränderten Binary-Datenbanktreiber. Die Prüfung vergleicht die vier Herstellerimages mit den gesperrten Originalidentitäten und die unteren Image-Layer der drei Anwendungsprofile mit dem Original-Python-Basisimage. Sie behauptet keine lokal nachgepatchten Bibliotheken und keine Entfernung von Herstellerpaketen. Der Abnahme-Gate verlangt weiterhin passende Inventar-/Policyhashes, sieben erfolgreiche Service-Artefaktprüfungen, höchstens 24 Stunden alte Nachweise und einen erfolgreichen Vulnerability-Gate. Neue Original-Images erhalten keine pauschale CVE-Ausnahme; historische Belege gelten nicht für geänderte Artefakte.

Die QA-Korrektur vom 23. November 2026 verwendet Nginx 1.30.7 Alpine Slim,
PostgreSQL 18.7 und n8n 2.48.8 mit überprüften Hersteller-Digests. Das
Anwendungsimage installiert zusätzlich das hashgesperrte Alpine-Paket
`krb5-libs 1.22.3-r0`. Das Postfix-Herstellerimage bleibt unverändert.

Die verbleibenden Bewertungen betreffen ungenutzte Herstellerkomponenten
beziehungsweise nicht erreichbare Aufrufpfade in der geprüften Konfiguration:
Kerberos-/Perl-/SQL-/XML-/Python-Zusatzmodule im Relay, nicht konfigurierte
rsyslog-Module, ungenutzte Netzwerkfunktionen der Go-Laufzeit in `gosu` sowie
nicht freigegebene n8n-Knoten und Eingabeformate. Das JWT-Muster im Pip-Cache
wurde als öffentliches Dokumentationsbeispiel überprüft. Jede konkrete
CVE-/Paket-/Versionskombination ist separat aufgelistet; das ersetzt keine
Paketkorrektur durch den Hersteller. Die Bewertungen laufen am 23. Dezember
2026 ab und sind bei Konfigurationsänderungen oder Upstreamupdates erneut zu
prüfen. Die vollständigen Scannerreports und SBOMs bleiben lokal erhalten.

Die Scannereingaben enthalten auch den Fingerprint der aktuellen Anwendungsquellen. Das Imagegate verweigert ein Anwendungsimage, dessen Buildlabel nicht zu diesen Quellen passt; Quelländerungen verlangen damit einen erneuten Build und Scan.

## Image-Nachprüfung am 25. November 2026

Die sieben gepinnten Dienste wurden nach dem Review neu gebaut beziehungsweise
als unveränderte Upstream-Artefakte geprüft und mit dem verifizierten Trivy 0.76.2
neu gescannt. Das Gate enthält keine neuen blockierenden Befunde. Alle 134
Einzelbewertungen wurden im neuen Scan wiedergefunden (135 Scannerzeilen wegen
mehrfacher Zuordnung); ihre Konfigurationsbelege stimmen weiterhin mit den
hinterlegten Hashes überein. Diese Befunde bleiben weiterhin ausdrücklich
bewertete Ausnahmen, keine Behauptung vollständig gepatchter Herstellerimages.
Ablaufdatum bleibt unverändert der **23. Dezember 2026**.

Die öffentlichen Docker-Hub-Taglisten wurden ebenfalls neu abgefragt. In den
betrachteten Versionsreihen sind unter anderem Nginx 1.30.8 und n8n 2.49.6/2.50.1
verfügbar; die betrachteten PostgreSQL-18- und Postfix-5-Reihen enthalten die
verwendeten Stände 18.7 beziehungsweise 5.2.1. Dieser Nachweis gilt für die
konkreten gepinnten Image-IDs im neuen Inventar. Andere Herstellerstände benötigen
einen eigenen Kompatibilitätslauf und neue Artefaktgates.

Lokale Nachweise: `.runtime/test-reports/phase-23-supply-chain/image-gate.json`,
`image-inventory.json`, die SBOM-/Scannerberichte sowie
`review-image-revalidation.json` und `review-vendor-updates.json` (inklusive
Abfragezeit und primären Registry-URLs). Die Integrations-CI führt die Gates
wöchentlich mit aktuellen Anwendungsartefakten erneut aus. Neue/veränderte Befunde,
geänderte Belege oder abgelaufene Bewertungen bleiben blockierend.
