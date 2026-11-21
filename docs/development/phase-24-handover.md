# Phase 24 – Übergabe

Einstieg: [Releaseverfahren](../deployment/release-and-recovery.md),
[Betriebshandbuch](../operations/platform-handbook.md),
[Administrator-/Benutzerhandbuch](../dashboard/platform-manual.md),
[186 Kriterien und 105 Invarianten](phase-24-acceptance.md),
[45 Aufgaben](phase-24-status.md).

Implementiert sind strikte Verträge, lokale inhaltsadressierte Releasebundles,
13 immutable Images, Offlinearchive, nichtmutierender Preflight, exklusiver
Deploymentlock, Hashjournal, kontrollierte Installation/Neustart/Migrationspläne,
unabhängig signierte Produktivgenehmigungen und authentifiziert verschlüsseltes
vollständiges Backup mit isoliertem Daten-/Rechte-/Credentialrestore.
Keine neue Fachlogik oder Infrastrukturtechnologie wurde eingeführt.

## Tatsächliche Nachweise und Bedienung

`make check` prüft Repositoryqualität; `make deployment-check` führt die
reversiblen Operator-/Vertrags-Negativtests aus. `CVE_DOCKER_SUDO=1 make
deployment-test` erzeugt eigene private Staging-/Recoveryprojekte und testet
Installation, Idempotenz, echte mTLS/Ansible-/Browserabläufe, kontrollierte
Fachkette, Gesamtbackup/Restore, Ausfallneustart und Offlineimageimport.
`make deployment-acceptance` konsolidiert nur vorhandene erfolgreiche Nachweise,
prüft ihre Releasebindung und erhält die Produktionssperre. Der private
Maschinenbericht ist der maßgebliche Abschlussstatus; keine pauschale
Erfolgserklärung in dieser vorab eingefrorenen Quellkopie.

Alle `.runtime/test-reports/phase-24-*` und die durch `phase-24-native-stage.json`
referenzierten Manifest-/Umgebungsdateien lokal sicher aufbewahren. Vollbackups
bleiben im eigenen Deploymentkontrollverzeichnis; Schlüssel getrennt unter
`.runtime/phase24-recovery-keys`, nur für dieses Labor. Produktionsaufbewahrung
und Key-Escrow sind separat einzurichten. Keine privaten Inhalte veröffentlichen.
Native Testcontainer/-volumes werden ausschließlich anhand ihres eigenen
zufälligen Projektnamens entfernt; normale und fremde Container bleiben erhalten.

## Erforderliche Betreiberentscheidungen

- Initialen Git-Commit ausdrücklich beauftragen (DEP-104); Repository hat noch
  keinen HEAD. Danach formalen Release erzeugen und die finale Freigabe an dessen
  tatsächliche Identität binden. Kein Push ohne separaten Auftrag (DEP-105).
- Produktionshost/-DNS, PKI/Trust/CRL und getrennte Secrets bereitstellen.
- Verantwortliche für DB/PKI/Freigabe/Incident und Rufbereitschaft benennen.
- Externe Überwachung, Aufbewahrung, Offsite-Transfer und getrennten Key-Escrow
  praktisch testen; RPO/RTO anhand realer Datenmengen vereinbaren.
- Reale Kapazitätsbudgets, Wartungsfenster und Ingress-Cutover festlegen.
- Erst danach konkrete Produktionsaktion mit begrenzter signierter Genehmigung
  freigeben; Mail und CVE-Erstbefüllung bewusst getrennt aktivieren.

Entwicklungskandidat, bestandene Stagingtests und Signaturunit-Tests sind keine
Genehmigung für diese Produktionshandlungen. Ein fehlender Gitbezug wird nicht
mit einem erfundenen Commit oder einem synthetischen Freigabevermerk verdeckt.
