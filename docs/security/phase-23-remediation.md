# Behebung der Lieferkettenbefunde in Phase 23

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Die Ausgangsberichte mit 694 blockierenden Fundstellen bleiben unter `.runtime/test-reports/phase-23-pre-remediation/supply-chain/` erhalten. Maßgeblich sind die abschließenden Scans und Komponentenprüfungen der tatsächlich aktivierten 13 Artefakte. Es gibt keine Ignoreliste und keine genehmigten Ausnahmen.

| Bereich | Maßnahme |
|---|---|
| Acht Python-Dienste | Gepinnte CPython-3.12.16-/Alpine-Basis; SQLite 3.54.1 und Expat 2.10.0. Das Python-Expat-Modul wird aus dem unveränderten CPython-Quellarchiv gegen die korrigierte Systembibliothek gebaut. |
| PostgreSQL-Treiber | Psycopg 3.3.8 verwendet die C-Implementierung mit System-libpq 18.6. Das zuvor verwendete Binary-Wheel brachte eigene, vom OS-Scanner nicht vollständig bewertete Kerberos-/OpenSSL-/LDAP-Bibliotheken mit. Es wird nicht mehr installiert. TLS mit `verify-full` bleibt erhalten; GSS-Verschlüsselung ist ausdrücklich deaktiviert. |
| PostgreSQL 18.6 | Neu aus festem Quellarchiv mit den bisherigen benötigten Optionen gebaut; ungenutzte XML-/XSLT-Erweiterungen und Bibliotheken entfernt. Der optionale LLVM-JIT wird ebenfalls nicht mitgeliefert, da er die alte XML-Bibliothek erneut einbindet; SQL-Auswertung, Constraints und Erweiterungsverträge bleiben bestehen. Kerberos 1.22.3; gosu 1.20 aus festem Commit mit Go 1.27.3 und x/sys 0.44.0 neu gebaut. Kein Compiler im Laufzeitimage. |
| Nginx 1.30.6 | Gepinnter offizieller Digest; die nicht geladenen dynamischen NJS-/XSLT-Module und dadurch nicht mehr benötigten XML-Bibliotheken entfernt. Die geschlossene Anwendungskonfiguration verwendet diese Module nicht. |
| Envoy 1.40.2 | Server unverändert; ungenutzte Login-/PAM-/RPC-/Kerberos-Pakete und APT entfernt. Dies betrifft ausschließlich das eigene Containerimage. Bash, Coreutils und der native Envoy-Server bleiben für Start und Healthcheck erhalten. |
| Postfix 3.11.7 | Signierte Alpine-APKs auf derselben korrigierten Pythonbasis, ohne Datenbanktreiber. UID/GID 100/101 und postdrop-GID 102 bleiben zum vorhandenen Queuevolume kompatibel. Native Queue-, SASL- und TLS-Funktionen bleiben erhalten. |
| Node 24.22.2 | Aus geprüftem Quellarchiv mit gemeinsam genutztem SQLite 3.54.1 und Brotli 1.2.1 neu gebaut. Die tatsächlich eingebundenen Bibliotheken werden über `process.versions`, Buildoptionen und Funktionsproben geprüft. |
| n8n 2.46.7 | Offizielles npm-Release mit eigenem Integritätslock und gezielten Sicherheitsupdates auf der korrigierten Nodebasis. Nicht benötigte Paketmanager und der ungenutzte native Go-TypeScript-Compiler sind im Laufzeitimage nicht enthalten. Produktionsmodus und stabiler Releasekanal sind ausdrücklich gesetzt. |

`scripts/hardening/runtime_images.py` prüft Quellen-/Paket-SHA256, Go-Modulhashes und npm-Integritäten. Signierte APKs werden ohne `--allow-untrusted` installiert. Abschließende Dockerbuilds laufen mit `--network none`, npm mit `ci --offline --ignore-scripts`. Fehlerhafte oder fehlende Artefakte brechen den Build ab. Sources, Dockerfiles und Locks gehören zum Inputhash; Compiler bleiben in separaten Buildstufen. Ein erstmaliger Node-Quellbuild kann deutlich länger dauern als ein gewöhnlicher Imagebuild.

Der erste Alpine-Scan meldete bereits null blockierende Befunde. Die zusätzliche Prüfung der eingebetteten Bibliotheken fand dennoch alte Python-Parser, Node-Bibliotheken und die Bibliotheken des Binary-Treibers. Deshalb reichen OS-Scans allein für die Abnahme nicht aus. `scripts/hardening/components.py` prüft die unveränderlichen Image-IDs zusätzlich nativ. Fehlende, veraltete oder zu einem anderen Inventar beziehungsweise einer anderen Prüfpolicy gehörende Ergebnisse sperren die Abnahme.

Der PostgreSQL-Portabilitätstest startet einen vorhandenen Debian-Cluster mit dem neuen musl-Image und vergleicht beide Anwendungsdatenbanken, Rollen-Credentials und indizierte Unicode-Sortierung. Die Anwendungsdatenbanken verwenden bereits `PG_UNICODE_FAST`. Andere Bestandsdatenbanken mit libc-Anwendungslocales benötigen einen eigenen Migrationsplan. Der normale Cluster wird beim Wechsel nicht neu initialisiert.

n8n bleibt auf den bisherigen eingeschränkten Funktionsumfang begrenzt: zugelassene Knoten, PostgreSQL, interne HTTPS-Ansteuerung und Notification-/SMTP-Flows. Öffentliche UI/API, Communitypakete, Task Runner und beliebige Codeknoten bleiben gesperrt. Sechs Workflowdefinitionen und zwei verschlüsselte Credentials werden beim Imagewechsel nicht neu installiert. Die Updates sind keine Freigabe zusätzlicher Integrationen.

Initiale Fehlerberichte bleiben erhalten. Korrigiert wurden unter anderem ein verlorenes Ausführungsrecht am Mail-Startskript, ein veralteter Mail-Imagetag im Namespacefilter und eine Testannahme über leere Notification-Tabellen bei gemeinsam ausgeführten Statusprüfungen. Die abschließende Envoy-Bereitschaftsprüfung verwendet `--no-recreate`, damit ein bereits gebundener Namespace nicht ersetzt wird.

Beim abschließenden normalen Runtimewechsel war das kurzlebige Entwicklungs-Serverzertifikat des Mail-Relays inzwischen abgelaufen. Es wurde mit der vorhandenen CA für 14 Tage erneuert; privater Serverschlüssel, CA, Client-Pins, Policy, Credentials und Queue blieben erhalten. Alter Leaf und ein Nachweis ohne private Schlüsselwerte liegen privat vor. Der erste fehlgeschlagene Startbericht bleibt erhalten. Nach der Erneuerung und erneuter Namespacebindung sind alle 13 Dienste gesund und mit dem finalen Inventar identisch.

Der Livevergleich prüft 133 geschützte Anwendungstabellen. 132 sind identisch; ausschließlich die zuvor leere Notification-Empfangstabelle enthält vier neue interne Statusbelege. Alle vier sind gegen die eigene Status-Outbox, bestehende Incidents, Ereignisversionen und zulässige Verarbeitungsergebnisse geprüft. Es wurden keine Auditzeilen gelöscht und keine echten Benachrichtigungen erzeugt.
