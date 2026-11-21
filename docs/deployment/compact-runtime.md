# Drei eigene Container, ein Anwendungsimage

Der reguläre CVE-Mon-Stack besteht aus sieben laufenden Containern. Die drei eigenen Container verwenden dasselbe Image `cve-application:0.24.0`; nur dieses Anwendungsimage wird gebaut. Nginx, PostgreSQL, Postfix und n8n bleiben unveränderte, mit Digest gesperrte Docker-Hub-Images.

| Container | Enthaltene Module | Interne Endpunkte |
|---|---|---|
| cve-api | API, Anmeldung, Verwaltung, Inventarannahme, Status | cve-api:8000 |
| cve-processing | Event Dispatcher, Inventory, Matcher, Findings, Notification, Importer, Enricher | Dispatcher :8001; Inventory :8002; Matcher :8003; Findings :8004; Notification HTTPS :8000; Importer :8005; Enricher :8006 |
| cve-sources | Ansible SSH Executor | Ansible :8000 |

Die bisherigen logischen DNS-Namen bleiben als Docker-Netzwerkaliase erhalten. Die Notification-Adresse `https://cve-notification:8000` bleibt insbesondere für bestehende n8n-Workflows und Credentials gültig. Das Dashboard wird weiterhin statisch vom Original-Nginx ausgeliefert. Die Workerports werden nicht auf dem Host veröffentlicht.

## Bauen und starten

```sh
./cve_mon setup
./cve_mon --sudo start
./cve_mon --sudo health
```

Der Builder erzeugt alle eigenen Python-Wheels gemeinsam, installiert hashgesperrte Abhängigkeiten auf dem Original-Python-Image und baut ohne Netzwerkzugriff. Ein Fingerprint der Quellen, Abhängigkeiten und Buildanweisung verhindert wiederholte Builds bei unveränderten Eingaben. In Compose besitzt ausschließlich die API eine Builddefinition; beide Worker-Profile beziehen dasselbe fertige Image. `./cve_mon` ist der einzige lokale Einstieg; die Make-Ziele sind Kompatibilitätsaliase. Produktionsrollouts benötigen weiterhin den autorisierten Releasecontroller und gültige Sicherheitsnachweise.

Der zentrale Controller baut fehlende oder geänderte Dashboard-Assets automatisch. Die im Repository enthaltenen n8n-Workflows werden bei jedem n8n-Containerstart
automatisch importiert und veröffentlicht, auch bei einer leeren Erstinstallation:

```sh
./cve_mon --sudo start
```

Bestehende Workflows werden beim normalen Start nicht neu installiert. `./cve_mon --sudo stop` und der Alias `make application-down` stoppen den gesamten Stack inklusive Hostcontroller. Historische Make-Ziele wie `matcher-up` und `importer-up` bleiben verwendbar, steuern aber jetzt die gesamte zugehörige Prozessgruppe. Entsprechend stoppt beispielsweise `matcher-down` auch die anderen Module von `cve-processing`.

## Prozessführung und Grenzen

Die sieben Verarbeitungs- und Quellenmodule beziehungsweise der SSH-Executor laufen als getrennte Python-Prozesse. Sie behalten eigene Datenbankrollen, Verbindungspools, Jobregistrierungen, Leases und Transaktionen. Der gemeinsame Supervisor leitet Beendigungssignale weiter und räumt verbliebene Prozesse auf. Der Ausfall eines Kindes beendet seine Nachbardienste nicht. Neustarts verschiedener Rollen laufen unabhängig; gespeicherte vorübergehend fehlgeschlagene Jobs werden über n8n wieder aufgenommen. Siehe [Worker-Recovery](../operations/worker-recovery.md). Der Gruppen-Healthcheck prüft alle Kinder und ihre Bereitschaft. Notifications besitzen zusätzlich eine gesonderte Bereitschaftsprüfung für n8n und SMTP; ein Ausfall dieser Abhängigkeiten wird dadurch separat sichtbar.

Container teilen innerhalb einer Gruppe Netzwerknamespace, Ressourcenbudget, Unix-Benutzer und die gemounteten Konfigurationen. Die bisherigen Containergrenzen zwischen diesen Modulen entfallen. Die getrennten Datenbankrollen bilden deshalb innerhalb einer kompromittierten Gruppe keine vollständige Secret-Isolation. Die API besitzt weiterhin ausschließlich ihre eigenen Konfigurationsmounts; der Quellencontainer erhält keine API- oder Notification-Secrets.

Die Verarbeitung verwendet die internen Datenbank- und Callback-Netze sowie `cve_outbound` für direkte HTTPS-Verbindungen. Postfix stellt direkte SMTP-Verbindungen zu den gespeicherten zentralen oder persönlichen Servern her. Die Transportmodule prüfen weiterhin Quellen und Pfade; Namespace-Regeln begrenzen private Ziele. Scratch-Verzeichnisse bleiben getrennt unter `/work/importer` und `/work/enricher`. [Direkter Netzwerkbetrieb](direct-outbound.md).

Beide Worker-Container warten vor dem Start der Kinder auf eine neue, an Netzwerknamespace und Bootkennung gebundene Freigabe des Hostcontrollers. Nach einem unkontrollierten Containerneustart bleibt die Gruppe gesperrt, bis `./cve_mon --sudo start` die Netzfilter erneuert. Ein bloßes `docker compose restart` ersetzt diesen kontrollierten Wiederanlauf nicht.

## Umstellung und Wiederherstellung

Für einen noch laufenden Entwicklungsstack mit den bisherigen 13 Containern:

```sh
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.application.migration
```

Der Controller prüft den vorhandenen Projektumfang, baut das gemeinsame Image, stoppt die Schreibdienste kontrolliert und erstellt eine verschlüsselte Sicherung beider Datenbanken, der gestoppten Postfix-Queue, Konfigurationen, PKI und n8n-Schlüssel. Der Schlüssel liegt separat unter `.runtime/security/`; die Sicherung liegt unter `.runtime/consolidation/`. Erst nach vollständiger Sicherung werden die sieben alten Worker-Container entfernt. Datenvolumes und vorhandene Konfigurationsverzeichnisse werden dabei nicht gelöscht. Passwörter, Benutzer-/MFA-Zustand, Workflows und verschlüsselte Credentials werden vor und nach der Aktivierung verglichen.

Die Release-/Scaninventare, das Release-Schema, Startcontroller und Recovery-Controller beziehen sich auf sieben reguläre physische Services (MailHog nur für optionale Mailtests). Die drei Anwendungsprofile müssen dieselbe unveränderliche Image-Identität besitzen. Offline-Exporte speichern das gemeinsame Image einmal; die drei Serviceeinträge verweisen auf dasselbe Archiv. Eine vollständige Wiederherstellung startet die neuen Gruppen und erzeugt deren Namespacefreigaben neu. Historische Sicherungen und Nachweise des 13-Container-Stacks sind als solche zu behandeln; sie stellen keine Freigabe des neuen Quellstands dar.

Sicherheitsbefunde aus den unveränderten Herstellerimages werden weiterhin erfasst und sperren das Produktionsfreigabegate. Die Zusammenlegung ist keine Behebung dieser Befunde und führt keine automatischen Ausnahmen ein.

## Prüfstand vom 12.11.2026

Die laufende Entwicklungsinstallation wurde von 13 auf acht gesunde Container umgestellt. Drei Container verwenden nachweislich dasselbe Anwendungsimage und dessen Build-Fingerprint stimmt mit den aktuellen Quellen überein. Die fünf Herstellerimages und ihre Entrypoints sind unverändert. Benutzer, Passwörter, MFA-Zustand, Workflows und verschlüsselte n8n-Credentials sind vor und nach der Umstellung identisch. Ein Browserlauf bestätigt vertrauenswürdiges TLS, den bisherigen Login und weiterhin optionale MFA.

Bestanden sind 701 allgemeine Tests, vier Tests der Prozessgruppen einschließlich Ausfall und kontrolliertem Wiederanlauf, 78 Envoy-Tests und elf Notification-Integrationstests einschließlich des vollständigen n8n-/SMTP-Wegs. Die verschlüsselte Migrationssicherung wurde außerdem in ein neues isoliertes Projekt wiederhergestellt: Beide Datenbank-Fingerprints, Kataloge und Rollenattribute stimmen überein; die Queue und Schlüssel wurden wiederhergestellt, alle acht Dienste waren gesund und beide n8n-Credentials ließen sich verifizieren. Anschließend wurden die isolierten Container, Volumes und wiederhergestellten privaten Konfigurationen entfernt.

Der Scan der acht laufenden Serviceeinträge enthält 185 blockierende Befunde, ohne Ausnahmen. Die Anzahl ist eine Zählung über Images und bedeutet keine Behebung der bisherigen Herstellerbefunde. Das Produktionsfreigabegate bleibt gesperrt. Prüfberichte und SBOMs: `.runtime/test-reports/compact-supply-chain/`; zusammengefasster Betriebsnachweis: `.runtime/test-reports/compact-runtime-acceptance.json`. Nextcloud blieb unverändert. Es wurde kein Commit erstellt.

Die optionale [Ansible-Erfassung](../operations/managed-ansible.md) verwendet das neue Netz
`cve_ssh`. Der SSH-Executor erhält ausschließlich seine eigenen Zugangsdaten und einen
flüchtigen privaten Arbeitsbereich. Importer und Enricher erreichen ihre Quellen weiterhin
ausschließlich über Envoy. Das lokale Steuerprogramm wird bei verfügbarem Benutzer-systemd
als automatisch neu startender Dienst geführt. Nach einem Host-Neustart erfolgt der
kontrollierte Wiederanlauf wie oben mit `./cve_mon --sudo start`.
