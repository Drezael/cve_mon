# Original-Images aus Docker Hub

Die vier regulären Infrastrukturservices und der optionale Mailtest verwenden unveränderte, durch Version und Digest gesperrte Docker-Hub-Images. `infrastructure/images.lock.json` ist der gemeinsame Versionsvertrag; `compose.yml` enthält dieselben Referenzen. Keine eigenen Hersteller-Dockerfiles, Paketentfernungen, npm-Overrides oder selbst kompilierten Laufzeiten. Zusammen mit drei eigenen Anwendungsprofilen laufen sieben CVE-Mon-Container; MailHog kommt nur im Mailtest hinzu. Siehe [kompakter Betrieb](compact-runtime.md).

| Service | Original-Image |
|---|---|
| Eingang | nginx:1.30.6-alpine |
| Datenbank | postgres:18.6-alpine3.24 |
| Mail | boky/postfix:5.2.1-alpine |
| Automation | n8nio/n8n:2.46.7 |
| Lokaler Mailtest | mailhog/mailhog:v1.0.1 |
| Basis der acht eigenen Dienste | python:3.12.16-alpine3.24 |

Nginx, PostgreSQL und Python sind Docker Official Images; n8n stammt von ihren Herstellern. Postfix stammt vom gepflegten Communityprojekt boky/postfix. Alle kommen direkt von Docker Hub, ohne Umverpackung unter eigenen Tags. Die acht Python-Module werden gemeinsam in einem Anwendungsimage für drei Profile gebaut; ihre unveränderten Abhängigkeits-Wheels sind mit Hashes gesperrt.

Vorhandene Projektcontroller und Make-Ziele bleiben verwendbar. `CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.hardening.runtime_images` lädt fehlende Original-Images. Der historische Funktionsname `build` bedeutet dort ausschließlich „lokal vorhandenes Original prüfen, sonst pull“. Ein wiederholter Start löst keinen Build der Fremdsoftware aus. Lokale vorhandene Digests erlauben weiterhin Offline-Starts. `make mail-build` bleibt als kompatibler Download-Aufruf erhalten.

Nginx, PostgreSQL, Postfix und der optionale MailHog starten mit ihrem
Original-Entrypoint. n8n führt davor einen read-only eingebundenen Repository-Wrapper
aus, der bei jedem Containerstart die verwalteten Workflows importiert und
veröffentlicht. Anschließend ruft er den unveränderten Hersteller-Entrypoint auf.
Das Herstellerimage selbst wird nicht verändert. TLS, Zugriffsregeln, Ressourcenlimits, Healthchecks und Workflow-Einschränkungen werden über Konfiguration, Umgebungsvariablen und schreibgeschützte Mounts festgelegt. PostgreSQL-TLS wird durch den Hostcontroller in einem separaten privaten Konfigurationsvolume mit den vom Originalimage benötigten Besitzrechten bereitgestellt; der kurzlebige Kopierhelfer verwendet ebenfalls das Originalimage. Auf frischen Installationen zuerst die vorhandenen Prepare-/Secrets-Ziele ausführen und PostgreSQL über den Projektcontroller starten. Danach funktionieren auch gewöhnliche Compose-Neustarts mit dem vorbereiteten Volume.

Postfix nutzt den vom Image vorgesehenen `/docker-init.d`-Hook ausschließlich zum Erstellen nativer main.cf/master.cf, TLS- und Policy-Dateien. Die Konfiguration wartet auf die hostseitigen Netzfilter, bevor der unveränderte Hersteller-Supervisor Postfix startet. Eine native rsyslog-Vorlage protokolliert ausschließlich Zeit, Komponente, Queue-ID, Schweregrad und begrenzte Transportereignisse. Nachrichten, Empfänger, Zugangsdaten und freie SMTP-Antworten werden nicht protokolliert. HTTPS- und SMTP-Verbindungen gehen direkt zu ihren konfigurierten Zielen. Ein ausgehender Proxy wird nicht mehr gestartet. Die bestehenden Hostcontroller richten die Namespace-Regeln ein. [Betrieb ohne Egress-Proxy](direct-outbound.md).

Datenbankvolume, Postfix-Queue, n8n-Daten und Verschlüsselungsschlüssel bleiben bestehen. Kein `down -v`, kein Reinitialisieren und keine Löschung bestehender Workflow-IDs für ein Imageupdate; der Container aktualisiert die verwalteten Definitionen automatisch. Vor einem Versionswechsel verschlüsselte konsistente Sicherung erstellen. Drittsoftware ausschließlich durch ein geprüftes neueres Upstream-Image aktualisieren; Version/Digest in Lock und Compose sowie gegebenenfalls Python-Dockerfiles gemeinsam ändern und native Regressionstests ausführen.

Die bisherigen Phase-23-Scans belegen historische Eigenbauten. Sie sind keine Sicherheitsfreigabe dieser Original-Images. Aktuelle SBOMs und Vulnerability-Gates bleiben erforderlich und erhalten keine automatischen Ausnahmen. Komponentenprüfungen erfassen nun die tatsächlichen Herstellerversionen und unveränderten Image-Identitäten, statt lokal nachgepatchte Bibliotheksversionen vorauszusetzen. Nicht behobene Herstellerbefunde blockieren eine formale Produktionsfreigabe weiterhin.

Prüfstand vom 11.11.2026: Der Entwicklungsstack wurde mit allen 13 Diensten gesund aktiviert; die laufenden Image-Identitäten stimmen mit dem abschließenden Scaninventar überein. Vorhandene Passwortdaten, Workflows und verschlüsselte n8n-Credentials sind unverändert; beide Credentials wurden erfolgreich entschlüsselt und geprüft. Browserprüfung mit vertrauenswürdigem TLS, bestehendem Login und weiterhin optionaler MFA erfolgreich. Funktionale Regression: 699 allgemeine Tests, 189 PostgreSQL-Tests, 77 Envoy-Tests, 36 Mail-Tests, zusätzlicher nativer Log-Sicherheitstest und vollständiger Notification-E2E-Test bestanden. Die verschlüsselte Sicherung liegt privat unter `.runtime/upstream-migration/`; der Schlüssel liegt separat.

Der abschließende Scan der 13 aktivierten Images enthält **265 blockierende Scanbefunde** (Befunde können in mehreren Images wiederholt auftreten). Die Herstellerimages wurden dafür nicht verändert, keine Ausnahmen hinzugefügt und kein grünes Security-Gate behauptet. Eine Produktionsfreigabe bleibt gesperrt. Inventar, SBOMs und Scanberichte liegen unter `.runtime/test-reports/upstream-supply-chain/`; der zusammengefasste Betriebsnachweis unter `.runtime/test-reports/upstream-image-migration.json`. Nextcloud wurde nicht verändert. Es wurde kein Commit erstellt.
