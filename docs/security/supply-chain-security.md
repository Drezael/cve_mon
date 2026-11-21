# Lieferkette und SBOM Phase 23

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Trivy 0.76.2 wird lokal unter .runtime/hardening/tools installiert. SHA256 der offiziellen Linux-64bit-Distribution: bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf. Sowohl Download als auch installierte Binärbytes werden vor jedem Scan geprüft. Installation: make security-tools. Kein Scanner erhält einen Docker-Socketmount; der Operator exportiert Kandidatenimages über die vorhandene Docker-CLI, anschließend scannt Trivy ausschließlich das Archiv.

make security-dependencies scannt Runtime-, Entwicklungs- und npm-Lockgraph inklusive Development-Abhängigkeiten getrennt und erzeugt CycloneDX-SBOMs. make security-images löst alle acht physischen Composeartefakte auf unveränderliche Image-IDs auf, erzeugt jeweils Rohreport/SBOM und ein Imageinventar. Abbrüche, fehlende Paketinventare und unbekannte Scannerschwere ergeben keinen erfolgreichen Gate. HIGH/CRITICAL/UNKNOWN blockieren auch ohne verfügbaren Fix. Es gibt keine automatische Ignore-/Ausnahmeliste.

make phase-23-acceptance prüft konkrete Berichte und gibt bei fehlenden Nachweisen oder offenen Imagebefunden NO_GO zurück. Lokale Provenienz enthält Quellhashes, Scannerhash und Inventar, keine Secrets/Env-Werte. Sie ist keine signierte SLSA-Attestation. Scanner-DB-Datum und genaue Artefaktversion bleiben Teil der Rohreports; ein Scan ist zeitgebunden und keine Zertifizierung. Runtime-/Devlocks und gepinnte CI-Actions bleiben erhalten. Es erfolgt kein Registry-Push.

Grundlagen: [Trivy Vulnerability Scanning](https://trivy.dev/docs/v0.76/guide/scanner/vulnerability/) und [SBOM](https://trivy.dev/docs/v0.76/guide/target/sbom/).

Die Dependencyprüfung umfasst vier eigene Graphen: Runtime, Entwicklung, Frontend und Python-Buildwerkzeuge. n8n wird ausschließlich als unverändertes Herstellerimage geprüft; ein lokaler npm-Overridegraph existiert nicht mehr. Das gemeinsame Anwendungsimage installiert hashgesperrte Wheels auf dem unveränderten offiziellen Python-Image. [Original-Images und Aktualisierung](../deployment/upstream-images.md).

OS-Scanner können eingebettete Bibliotheken oder verzögerte Distributionsmeldungen übersehen. Deshalb erfasst `scripts/hardening/components.py` zusätzlich die tatsächlichen SQLite-/Expat-/OpenSSL-/Node-Versionen und den unveränderten Binary-Datenbanktreiber. Die Prüfung vergleicht die fünf Herstellerimages mit den gesperrten Originalidentitäten und die unteren Image-Layer der drei Anwendungsprofile mit dem Original-Python-Basisimage. Sie behauptet keine lokal nachgepatchten Bibliotheken und keine Entfernung von Herstellerpaketen. Der Abnahme-Gate verlangt weiterhin passende Inventar-/Policyhashes, acht erfolgreiche Service-Artefaktprüfungen, höchstens 24 Stunden alte Nachweise und einen erfolgreichen Vulnerability-Gate. Neue Original-Images erhalten keine pauschale CVE-Ausnahme; historische Belege gelten nicht für geänderte Artefakte.
