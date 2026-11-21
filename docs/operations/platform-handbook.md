# Betriebshandbuch und Dienstkatalog

Die Plattform läuft auf einem Compose-Host. PostgreSQL ist die einzige fachliche
Datenhaltung und Job-/Outbox-Persistenz. Die Zuständigkeit für Host, PKI,
Freigaben, Offsite-Backup, Rufbereitschaft und Eskalation muss der Betreiber vor
Produktionsstart namentlich besetzen. Hier werden keine Betreiber oder
Produktions-SLOs erfunden. Maßgeblich sind [Deployment](../deployment/release-and-recovery.md)
und [Phase-24-Nachweise](../development/phase-24-acceptance.md).

## Dienste, Persistenz und Abhängigkeiten

| Dienst | Aufgabe und Voraussetzung | Dauerhafte Daten / Störungsauswirkung |
|---|---|---|
| cve-postgres | TLS, getrennte Rollen; zuerst starten | cve_monitoring und n8n; Ausfall stoppt fachliche Transaktionen |
| cve-egress-proxy | geprüfte Policy und aktuelle Namespacebindungen | Projektpolicy/Clientbindungen; Ausfall blockiert externen Zugriff |
| cve-mail-relay | eigene UID/GID, TLS/Auth; kontrollierter Envoy | persistente Postfix-Queue; Annahme ist noch keine Zustellung |
| cve-n8n | n8n-DB, unveränderter Encryption-Key, Service-Credentials | Workflows/Credentials in DB, Schlüssel und lokale n8n-Daten; keine Fachlogik ersetzen |
| cve-api | DB-Schema, Rollen, Auth-/MFA-/Servicekeys | fachliche Daten nur PostgreSQL; Eingangsannahme atomar persistiert |
| cve-event-dispatcher | PostgreSQL-Outbox, interne HTTPS-Empfänger | Leases, Fencing und Zustellbelege in DB |
| cve-inventory | persistente Uploadstaging-Daten | normalisierte unveränderliche Snapshots in DB |
| cve-importer | Importerrolle, Sources/Envoy-Guard | Quellenrevisionen/Checksums in DB; keine automatische Erstbefüllung |
| cve-enricher | Quellenrevisionen, Enricherrolle/Envoy | CVSS/EPSS/KEV-Provenienz in DB |
| cve-matcher | Snapshots, CVE-Revisionsbasis | Matches und Evidenz atomar in DB; Unknown ist keine Entwarnung |
| cve-findings | Matching-Outbox, Findingsrolle | stabile Findingidentitäten, Episoden, Historie, Audit in DB |
| cve-notification | Findingereignis, freigegebene Regeln, n8n | Intents, Deduplizierung, Fencing, Delivery-State in DB |
| cve-nginx | gerendertes TLS/mTLS, Releasefrontend, API/n8n | öffentliche HTTP/HTTPS-Grenze; kein Ersatz für API-ACL |

Nur Nginx veröffentlicht Hostports. PostgreSQL/n8n/Mail/Worker erhalten keine
öffentlichen Hostports. Die bestehenden Compose-Netze trennen Ingress, DB,
Fachdienste, Automation und Egress. Die minimalen Postfix- und Envoy-
Sonderrechte sind in den vorhandenen Topologie-/Sicherheitsprüfungen begrenzt.
Kein Dienst erhält Docker-Socket, keine weiteren Broker, keine direkten
SSH-Verbindungen zu inventarisierten Servern. Verteilte Hochverfügbarkeit oder
Multi-Host-Cutover wurden nicht zugesagt. Auf allen Ebenen gilt: Dienstbereitschaft
ist von fachlicher Frische und Verarbeitungsfortschritt zu unterscheiden.

## Regelbetrieb, Überwachung und Alarmierung

Täglich beziehungsweise nach Betreiberplan: Gesundheitszustände, frische
Statusproben, älteste fällige Jobs/Outbox, abgelaufene Leases, Importfrische,
Snapshotalter, Notification-Reconciliation, Queue-Rückstand, Disk/Inodes,
Zertifikatsrestlaufzeit und letzte getestete Sicherung kontrollieren. Ein alter
grüner Status ist keine Entwarnung. Der Statuscollector hat keine Reparaturrechte.
Technische Liveness, Readiness, Functional Health und Freshness stehen im
[Statusbetrieb](../status/health-contracts.md) und in der bestehenden Statusdokumentation.
Öffentliche Statusinformationen enthalten keine Secret-/Hostdetails; geschützte
Detailendpunkte benötigen die normalen Berechtigungen.

Ein unabhängiger externer HTTPS-Probe außerhalb dieses Hosts ist vor Produktion
vom Betreiber bereitzustellen; ein auf demselben ausgefallenen Host laufender
Collector kann keinen Totalausfall melden. Alarmregeln deduplizieren Incidents;
Statusmeldungen dürfen keine rekursiven Benachrichtigungsstürme auslösen.
In Staging bleiben echte SMTP-Policies und produktive Notification-Regeln aus.
Ein kontrollierter lokaler Test-SMTP-Empfänger prüft Zustellung ohne reale Mail.

Wöchentlich/nach Plan: Restoreübung, Offsite-/Key-Recovery-Kontrolle,
Berechtigungsreview, Secret-/Zertifikatsinventar, Scannerfrische und
Kapazitätstrends. Ablaufdaten nicht erst bei Ausfall prüfen. Baseline und
Budgets aus Phase 23 bleiben verbindlich; der E2E-Test nutzt ausdrücklich ein
separates Profil mit höheren Ingressraten. Dieses Profil ersetzt keinen Test
der normalen Rate-Limits und ist kein Produktionsdefault.

## Kontrollierte Diagnose und Neustart

Alle Diagnoseaufrufe auf den expliziten Umgebungsvertrag und Bundle begrenzen.
Keine vollständigen `docker inspect`-/Environment-/SQL-Dumps in Tickets. Die
Deployment-CLI gibt nur knappe Ergebnisse bzw. Fehlertypen aus. Private Details
nur lokal mit Operatorrechten prüfen. Fehler nicht durch Tabellenlöschung,
Neuprovisionierung, ungeprüfte Passwortrotation oder Abschalten von TLS lösen.

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage smoke \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage restart \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
```

Ein kontrollierter Restart verwendet bestehende Daten/Keys, startet PostgreSQL
und gebundene Egressclients vor abhängigen Diensten und prüft anschließend alle
13 Images, DB-Rechte und HTTPS. Er migriert nicht und löscht keine Volumes.
Produktionsrestart benötigt die gesondert signierte Aktion `restart-services`.
Die native Übung stoppt API und Datenbank nur im eigenen Testprojekt.

## Incident-Runbooks

Jeder Incident: Zeit/Release/Umgebung und Symptome dokumentieren, fachliche
Auswirkung begrenzen, minimale private Evidenz sichern, Ursache beheben,
technische **und fachliche** Erholung bestätigen. Bei Sicherheitsverdacht Owner
eskalieren und Beweismittel erhalten. Wiederholungen erst nach Klärung der
Leases/Idempotenz; niemals einen SQL-Status blind auf erfolgreich setzen.

| Störung | Diagnose und sichere Reaktion | Prüfnachweis und Detailanleitung |
|---|---|---|
| PostgreSQL nicht bereit | Disk, TLS, DB-Health und Rollen prüfen; kontrollierter Restart, keine neue DB | vorhandene Daten/Head/Rollen und Wiederanlauf prüfen; [DB-Recovery](postgresql-backup-restore.md) |
| API nicht bereit | DB-Abhängigkeit, Readiness und private Fehler prüfen; kontrollierter Restart | geschützte Requests weiterhin 401, autorisierte Verarbeitung erfolgreich; [Python](python-service-troubleshooting.md) |
| Nginx/Ingress | Zertifikat/CRL, gerenderte Konfiguration und Backend prüfen; erst nach Validierung reloaden | TLS/mTLS und 200/401/404 prüfen; [Nginx](nginx-troubleshooting.md) |
| Envoy/Egress | Policy, erlaubtes Ziel und aktuelle Clientnamespacebindung prüfen; nach Neustart neu binden | erlaubtes Ziel erreichbar, unerlaubtes Ziel weiterhin gesperrt; [Envoy](envoy-troubleshooting.md) |
| Postfix/SMTP | TLS/Auth, Guard, Queue-ID und echten Upstreamstatus getrennt prüfen | keine falsche Zustellung/zweite Einlieferung; [Queue](postfix-queue.md), [Recovery](postfix-recovery.md) |
| n8n/Workflows | DB, Schlüsselidentität, aktive Workflowversion und mTLS-Credentials prüfen | Credentialentschlüsselung und idempotente Reconciliation; [n8n](../n8n/recovery.md), [Notifications](../notifications/delivery-status.md) |
| Inventory-Rückstand | persistente Submission/Schemafehler, Lease und Processorlog prüfen | gleicher Snapshot/keine doppelte Verarbeitung; [Inventory](inventory-recovery.md) |
| Importer/Quellen | Quellenfrische, Revision/Checksum, Retry und Envoy prüfen; gezielte Jobs | Provenienz erhalten, kein unkontrollierter Vollimport; [Import](cve-import-recovery.md) |
| Enrichment | upstreamfrische Revision/Jobfehler prüfen; begrenzt erneut verarbeiten | ältere Revisionen erhalten; [Enrichment](cve-enrichment-recovery.md) |
| Matching | Snapshot-/CVE-Basis, Queue/Lease und Vergleichsevidenz prüfen | Unknown bleibt Unknown; [Matching](matching-recovery.md) |
| Findings | Eventreceipt, Matchingbasis, Version/Fencing und Historie prüfen | gleiche Identität, lückenlose Historie; [Findings](finding-recovery.md) |
| Notification | Intent, Fencing, n8n-Ausführung und SMTPbeleg abgleichen | Reconciliation vor erneuter Submission; [Notifications](../notifications/delivery-status.md) |
| Migration | aktuellen/eindeutigen Head und Advisory-Lock prüfen; Plan/codehash kontrollieren | keine Runtime-DDL, keine pauschale Rückmigration; [Releaseverfahren](../deployment/release-and-recovery.md) |
| Zertifikat | Aussteller, Ablauf, CRL und Trust prüfen; kontrollierter Leaf-/Trustwechsel | positive und negative mTLS-Proben; [Rotation](certificate-rotation.md) |
| Token | Serverbindung/Scope/Ablauf/Widerruf und Empfangsbeleg prüfen | widerrufener Token erhält keinen Receipt; [Tokenrotation](inventory-credential-rotation.md) |
| Secret-Leak | Zugriff begrenzen, Evidenz sichern, betroffene Schlüssel gezielt rotieren | keine Secretwerte im Incidentticket; [Incident Response](incident-response.md), [Rotation](secret-rotation.md) |
| Datenintegrität | Writes kontrolliert stoppen, Evidenz/Backup prüfen, nicht manuell reparieren | Fingerprints/ACL/Audit vergleichen; [Verifikation](restore-verification.md) |
| Gesamtverlust/Restore | geprüften vollständigen Snapshot und separat hinterlegten Key beschaffen | neues leeres Projekt, DB+13Dienste+entschlüsselte Credentials; [Recovery](../deployment/release-and-recovery.md) |

Nicht jede manuelle Betriebsaktion ist in der neuen Kampagne erneut ausgeführt.
Der Abnahmebericht trennt die frischen Installations-/Ausfall-/Restoreübungen
von den für identische Images übernommenen Phase-23-Resilienz-/Sicherheitstests.

## Wartung und Übergabe

Keine unbeaufsichtigten Containerupdates. Jede Änderung an Images, Quellen,
Konfiguration oder DB-Plänen benötigt passende neue Nachweise. Archivierte
Audits/Findings/Snapshots nach der genehmigten Aufbewahrungsregel behandeln;
keine Historienlöschung als Fehlerkorrektur. Schlüsselrotation mit altem und
neuem Trust testen, Rollbackmaterial sicher aufbewahren. Verantwortliche,
Wartungsfenster, Sicherungsaufbewahrung, Eskalationskontakt, konkrete RPO/RTO
und Produktionskapazität sind im Betreiberübergabeprotokoll auszufüllen.
