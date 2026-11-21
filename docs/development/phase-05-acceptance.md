# Phase-5-Abnahme

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge und 53 Abnahmepunkte erfüllt.**

531 Tests bestanden: 189 Standardtests, 36 Postfix-Integrationstests, 77 Envoy-,
40 Infrastruktur- und 189 PostgreSQL-Regressionstests. Alle 34 MAIL-Invarianten geprüft.
`make check` einschließlich Ruff, Format, Mypy, Struktur-/Schema-/Compose-Prüfung
und Secret-Scan erfolgreich. Secret-Baseline unverändert.

Der vollständige Mail-Lauf dauerte 323,73 Sekunden; JUnit-Bericht:
`.runtime/test-reports/phase-05-mail.xml`. Die korrigierte echte TLS1.1-Fixture
wurde zusätzlich separat erfolgreich geprüft. Lokale Prüfprotokolle unter
`.runtime/test-reports/phase-05-*.log`. CI-Workflow integriert; kein Remote-CI-Lauf behauptet.

Postfix 3.10.13, Envoy 1.40.2. Echte isolierte Provider-/DNS-/TLS-Fixture, keine realen Empfänger.

| Nr. | Abnahmepunkt | Konkreter Nachweis |
|---|---|---|
| 1 | Postfix-Container startbar. | Deploymenttest/Bootstrap, postfix-check |
| 2 | Docker-Compose-Konfiguration gültig. | Beide Compose-Modelle, make check |
| 3 | Postfix-Version festgelegt. | Paket-Lock, native mail_version |
| 4 | Reproduzierbares Containerimage. | 32 SHA256-Artefakte; Offline-Build |
| 5 | Netzwerkzuordnung korrekt. | test_direct_egress_and_wrong_interface_are_denied |
| 6 | Keine öffentlichen SMTP-Ports. | test_effective_native_configuration |
| 7 | Kein Docker-Socket. | Striktes Compose-Mountmodell |
| 8 | Keine unnötigen Containerprivilegien. | Exakte Master-Capabilities, native Worker-UID |
| 9 | Interner SMTP-Listener funktionsfähig. | test_end_to_end_verified_tls_auth_and_delivery |
| 10 | SMTP-Banner korrekt. | Echte SMTP-Banner/EHLO-Einlieferung |
| 11 | EHLO funktionsfähig. | test_submission |
| 12 | STARTTLS intern verpflichtend. | Negative Einlieferung ohne TLS |
| 13 | Interne Serverzertifikate gültig. | Client prüft echte CA/Hostname |
| 14 | Clientzertifikat verpflichtend. | Negative Einlieferung ohne Clientkey |
| 15 | Nicht autorisierte Zertifikate abgelehnt. | Fremde/abgelaufene/nicht gepinnte Zertifikate |
| 16 | Fingerprint-Freigabeliste wirksam. | test_certificate_revocation_and_rotation |
| 17 | Keine allgemeine Netzwerk-Relayberechtigung. | Leere mynetworks, unlisted-Client abgelehnt |
| 18 | Kein Open Relay. | Autorisierung plus explizite Empfänger |
| 19 | Absender-Allowlist wirksam. | Sender-/Header-Negativtests |
| 20 | Nachrichtenlimits aktiv. | Übergröße und native Recipient-/Rate-Limits |
| 21 | Relayhost auf Envoy gesetzt. | Effektives postconf relayhost |
| 22 | SMTP-TCP-Weiterleitung funktioniert. | Provider empfängt Bodymarker nur über Envoy |
| 23 | SMTP Server-First funktioniert. | Echter 220-Banner vor Client-TLS/EHLO |
| 24 | Kein direkter externer SMTP-Zugang. | Namespace-Connect zu externem SMTP abgewiesen |
| 25 | Festgelegter externer Smarthost. | Fester Provider/SNI im TLS-Test |
| 26 | Externes STARTTLS verpflichtend. | no_starttls-Negativtest |
| 27 | Externe TLS-Zertifikatskette gültig. | foreign_ca/expired-Negativtests |
| 28 | Externer Zertifikatsname korrekt geprüft. | secure match/SNI + gültiger Versand |
| 29 | Falscher Zertifikatsname abgelehnt. | wrong_name: nur Envoy-Zertifikat abgewiesen |
| 30 | SMTP AUTH zum Smarthost funktioniert. | Provider prüft echtes AUTH; bad_auth-Test |
| 31 | Keine Klartext-Authentifizierung. | Providerzähler auth_before_tls bleibt null |
| 32 | Zugangsdaten geschützt. | Private Dateien, Mounttrennung, negative Preflights |
| 33 | Keine Secrets in Logs. | Logmarker- und Credential-Abwesenheit |
| 34 | Secret-Rotation geprüft. | test_credentials_rotate_without_queue_loss |
| 35 | Persistente Mailqueue vorhanden. | Named Volume mit nativen Queue-Dateien |
| 36 | Mailqueue übersteht Containerneustart. | Konkrete Queue-ID nach echtem restart |
| 37 | Mailqueue übersteht Container-Recreate. | Queue-ID bei geändertem Container erhalten |
| 38 | Temporäre Fehler führen zu Wiederholungen. | Automatischer Retry und 450-Recovery |
| 39 | Permanente Fehler werden korrekt behandelt. | 550-Bounce ohne Originalbody, Ablauf begrenzt |
| 40 | Queue-Limits funktionieren. | Größe, Freiplatzreserve und Lebensdauer |
| 41 | Speicherplatzfehler werden korrekt behandelt. | Backpressure und nicht schreibbare Queue |
| 42 | Interner Container-Healthcheck funktioniert. | Native Sockets/qmgr/Schreibprobe ohne Provider |
| 43 | SMTP-Statusprüfung vorbereitet. | Dokumentierter EHLO/STARTTLS/QUIT-Vertrag |
| 44 | Logs nachvollziehbar. | JSON-Queue-ID/DSN/Status/Redaktion |
| 45 | Container-Ressourcen begrenzt. | Compose CPU/RAM/PID/FD/Verbindungsgrenzen |
| 46 | Kein unkontrollierter Fallback. | Kein TLS-/AUTH-/MX-/Direkt-Fallback |
| 47 | Netzwerkisolation nachgewiesen. | Eigene Namespace-Filter; frühere Egress-Regression |
| 48 | Integrationstests erfolgreich. | Gesamtlauf make postfix-test |
| 49 | Sicherheitstests erfolgreich. | Alle Mailtests security-markiert; Negativfälle |
| 50 | Dokumentation vollständig. | Deployment/Sicherheit/Betrieb/Testmatrix/Status |
| 51 | Backup-/Restore-Konzept dokumentiert. | Offline-Backup und echte Wiederherstellung |
| 52 | Übergabe an spätere Fachphasen vollständig. | phase-05-handover.md |
| 53 | Keine unzulässigen Architekturänderungen. | ADR-0023; unveränderte Facharchitektur/Quellvorgaben |

## Sicherheitsinvarianten

| Invariante | Anforderung | Nachweis |
|---|---|---|
| MAIL-01 | Postfix ist der einzige vorgesehene SMTP-Mailrelay der Anwendung | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-02 | Keine öffentlichen SMTP-Ports | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-03 | Postfix verwendet ausschließlich die vorgesehenen internen Netzwerke | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-04 | Kein direkter externer SMTP-Zugang | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-05 | Externer SMTP-Verkehr erfolgt ausschließlich über Envoy | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-06 | Der externe Smarthost ist festgelegt | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-07 | Keine direkte MX-Zustellung | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-08 | Keine allgemeine Open-Relay-Funktion | Effektive native Konfiguration und Compose-/Namespace-Negativtests |
| MAIL-09 | Interne SMTP-Einlieferung benötigt STARTTLS | CA/Pin-/Sender-/Empfänger-Negativtests |
| MAIL-10 | Interne SMTP-Einlieferung benötigt ein autorisiertes Clientzertifikat | CA/Pin-/Sender-/Empfänger-Negativtests |
| MAIL-11 | Die interne CA allein verleiht keine pauschale Relayberechtigung | CA/Pin-/Sender-/Empfänger-Negativtests |
| MAIL-12 | Nicht autorisierte Clients werden abgelehnt | CA/Pin-/Sender-/Empfänger-Negativtests |
| MAIL-13 | Absender sind auf genehmigte Identitäten begrenzt | CA/Pin-/Sender-/Empfänger-Negativtests |
| MAIL-14 | Externe SMTP-Verbindung benötigt STARTTLS | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-15 | Externes SMTP-Zertifikat wird validiert | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-16 | Tatsächlicher Smarthost-Name wird geprüft | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-17 | Kein TLS-Klartext-Fallback | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-18 | SMTP AUTH nur über ausreichend gesicherte Verbindung | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-19 | Keine SMTP-Zugangsdaten in Envoy | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-20 | Keine SMTP-Zugangsdaten im Repository | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-21 | Keine SMTP-Zugangsdaten in Logs | Externes TLS/AUTH, falsche Identität und Credential-/Logtests |
| MAIL-22 | Persistente Postfix-Mailqueue | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-23 | Containerneustart darf Queue nicht löschen | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-24 | Temporäre SMTP-Fehler werden kontrolliert wiederholt | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-25 | Permanente SMTP-Fehler werden nachvollziehbar behandelt | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-26 | Begrenzte Mail- und Queue-Ressourcen | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-27 | Queue-Speicherplatzfehler werden erkannt | Native Queue-, Ablauf-, Backpressure-, Restart-/Recoverytests |
| MAIL-28 | Keine privilegierten Container | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-29 | Kein Docker-Socket | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-30 | Healthchecks versenden keine echten Nachrichten | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-31 | Ein externer Ausfall bedeutet nicht automatisch den Ausfall der internen Queue | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-32 | Testnachrichten erreichen keine unbeabsichtigten externen Empfänger | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-33 | Backup und Restore berücksichtigen die Vertraulichkeit der Mailqueue | Container-/Health-/Geheimnisprüfung und Backup/Restore |
| MAIL-34 | Sicherheitsrichtlinien werden durch Negativtests überprüft | Container-/Health-/Geheimnisprüfung und Backup/Restore |

## Grenzen und Betriebsfreigabe

Die Standardpolicy bleibt geschlossen. Reale Providerdateien, externe PKI, freigegebene
Empfänger/Clientpins und Host-Startautomation sind Betreiberaufgaben vor Produktivversand.
Dies blockiert den isolierten Nachweis der vollständigen Sicherheitskette nicht.
Nach unklarer DATA-Bestätigung sind SMTP-Duplikate möglich und explizit getestet.
Freiplatzmangel wird durch eine unerfüllbare Reserve simuliert; keine Host-Disk wird gefüllt.
Backup-Zielverschlüsselung und Volume-/Hostquotas werden extern bereitgestellt.
Keine Fachservices späterer Phasen vorgezogen, keine fremden Container geändert.
