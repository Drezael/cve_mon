# Kennzahlensemantik

Scope: aktive Server mit effektiver Sichtberechtigung; Finding-Zahlen zusätzlich mit findings_read. Servergesamtzahl zählt Server, betroffene Server zählt DISTINCT Server mit aktuellem affected-Matching und offenem Finding. Offene Findings umfassen open und in_progress; critical/high verwenden denselben Lebenszyklus. Überfällig folgt findings.current_findings.is_overdue. Potentially affected und unknown sowie die Verteilungen umfassen alle sichtbaren aktuellen Finding-Identitäten einschließlich beendeter Lebenszyklen; die Lifecycle-Verteilung macht dies sichtbar. KEV zählt ausschließlich den aktuellen Quellenstatus present, unabhängig von technischer Betroffenheit.

Mehrere betroffene Pakete erzeugen kein mehrfach gezähltes Finding. Gruppenverteilungen summieren sich nicht zu einem globalen Serverbestand. Inventarlücken: missing, stale gemäß aktiver Finding-Policy, not_configured ohne erfundene Frist sowie incomplete bei unvollständigem oder noch nicht erfolgreich verarbeitetem letzten Versuch. Matching pending/outdated/current berücksichtigt zusätzlich die Finding-ACL.

Verlauf: UTC-Kalendertage, 7/30/90 Tage. audit_events created, resolved, reopened und closed werden separat gezählt. Wiedereröffnung ist keine neue Finding-Identität. Die SVG-Linien verwenden eine gemeinsame Nullbasis und eine gemeinsame Skala. Vollständige Tabellenwerte sind erreichbar. Fehler erzeugen weder Null-KPIs noch künstliche Live-Zufallswerte.

Die Karte **CVE-Datenbank** zeigt den globalen öffentlichen Datenbestand: eindeutige CVE-Identitäten mit aktueller Enrichment-Revision sowie aktuelle Quelldatensätze. Ein Quelldatensatz kann dieselbe CVE wie andere Quellen beschreiben; diese Zahl ist deshalb keine Zahl eindeutiger CVEs. EPSS-Datensätze werden in einer eigenen Quellenzeile gezählt.

Das angezeigte Aktualisierungsdatum ist der neueste vollständig erfolgreiche Quellenimport, nicht der letzte Versuch oder der Zeitpunkt der Seitenabfrage. Die Tabelle zeigt pro Quelle Erfolg, letzten Versuch und Zustand; unvollständige oder fehlgeschlagene Versuche verschieben das Erfolgsdatum nicht. Ohne erfolgreichen Import erscheint ein ausdrücklicher Leerzustand. Während einer Aktualisierung wird alle fünf Sekunden, ansonsten alle 30 Sekunden nachgeladen.

**Datenbank aktualisieren** erfordert `cve:update` (standardmäßig ausschließlich die Administratorrolle), eine aktuelle Sitzung und CSRF-Prüfung. Die API legt vorhandene Importer- und EPSS-Jobs in der dauerhaften Queue an; Netzwerkzugriffe bleiben Aufgabe des Quellencontainers. Laufende Jobs werden wiederverwendet, dieselbe Idempotency-ID erzeugt auch nach Abschluss keine weiteren Jobs. Nur aktivierte und konfigurierte Quellen werden eingeplant; OSV benötigt explizite Ökosysteme. Der erste Quellenimport verwendet `initial`, spätere Importe `incremental`. EPSS verwendet den aktuellen Tagesfeed. **Ansicht neu laden** lädt ausschließlich die Kennzahlen neu.

Die API erhält über `scripts.services.manage.prepare` eine validierte Kopie der nicht geheimen Importerkonfiguration (`import-sources.json`) in ihrem bestehenden schreibgeschützten Konfigurationsmount. NVD-Schlüssel und Importer-Zugangsdaten werden nicht kopiert. Nach Änderungen an `sources.json` sind die API-Konfiguration und der Quellencontainer kontrolliert neu vorzubereiten. Ohne gültige Konfiguration bleibt die Statusanzeige verfügbar; Aktualisieren wird gesperrt. Die Migration `00033_cve_data_status` ergänzt Berechtigung, minimierte Lesefunktion und atomare Aktualisierungsanforderungen. Es entstehen keine zusätzlichen Container.

Die Fortschrittskarten unterscheiden drei Mengen: **Heruntergeladen / eingelesen** zählt
aktuelle validierte Quelldatensätze (`record_count`), **Verarbeitet** zählt CVE- und
Advisory-Identitäten mit vorhandener aktueller Enrichment-Revision und **Noch in der
Pipeline** zählt offene Aufbereitungsaufträge. Heruntergeladene Archive zählen erst nach
dem Einlesen ihrer Datensätze; EPSS-Scores stehen separat in der Quellentabelle. Diese
Zahlen sind wegen mehrerer Quellen je Identität und wiederholter Aufbereitung nicht
voneinander abzuziehen und bilden keinen erfundenen prozentualen Gesamtfortschritt.

Offene Aufträge sind `pending`/`queued` (wartend), `running` (in Verarbeitung) und
`retry_pending` (erneuter Versuch). Gezählt werden ausschließlich die aktuellen
Runtime-Jobs `cve.enrich.record`, `cve.enrich.reconcile`, `cve.enrich.backfill` und
`cve.epss.sync_daily`. Inventar-, Matching-, Finding- und Notification-Jobs gehören
nicht zur Aufbereitung der Quelldaten. Erfolgreiche beziehungsweise fehlgeschlagene
Aufträge werden zusätzlich als Historie angezeigt; abgebrochene Jobs sind keine offenen
Aufträge. Die Anzahl abgeschlossener Jobs ist keine Anzahl eindeutiger CVEs.

Die Lesefunktion `cve.dashboard_pipeline_status()` aus Migration `00035_pipeline_status`
liefert nur aggregierte Zähler an die bestehende API-Sicherheitsrolle. Ein abdeckender
partieller Index unterstützt die Abfrage; zusätzliche Counter-Schreibvorgänge im
Verarbeitungspfad entfallen. Bei laufenden Importen oder offenen Aufträgen wird alle
fünf Sekunden nachgeladen, ansonsten alle 30 Sekunden. Bei Abruffehlern erscheint die
bestehende Fehleranzeige; unbekannte Zähler werden nicht als null erfunden.

Migration `00036_read_path_reliability` hält die Anzeige unter laufenden großen Importen
innerhalb der Abfragebudgets: Die Quelldatensatzanzahl wird einmal gruppiert gelesen;
partielle Zählindizes vermeiden wiederholte vollständige Tabellenzugriffe. Für die
Systemüberwachung unterstützt ein separater, abdeckender Index die begrenzte Auswahl
der ältesten 10.001 offenen Jobs. Das bestehende `capped`-Signal bleibt unverändert.
Die aufwendige JIT-Kompilierung ist ausschließlich für diese Monitoring-Lesefunktionen
deaktiviert. Die Pflege der Jobtabelle erfolgt mit kleineren Autovacuum-/Analyse-Schwellen.

Die Indizes werden online mit `CREATE INDEX CONCURRENTLY` angelegt. Eine Sitzungssperre
hält die bestehende Migrationsserialisierung auch über die dafür erforderlichen
Autocommit-Abschnitte aufrecht; vor Abschluss wird die Transaktionssperre wiederhergestellt.
Ein unterbrochener Aufbau kann anhand der Indexgültigkeit fortgesetzt werden. Weder
Fencing-/Berechtigungsregeln noch fachliche Daten werden dabei umgeschrieben.

Die Quellenzeile bevorzugt einen laufenden beziehungsweise wiederaufgenommenen Import
gegenüber einem jüngeren abgebrochenen Versuch. Der Zeitpunkt des letzten Versuchs
berücksichtigt auch die Erstellung des Replay-Jobs; das Erfolgsdatum bleibt weiterhin
ausschließlich aus vollständig erfolgreichen Importen abgeleitet.

Gleichzeitige Aufrufe teilen innerhalb einer API-Instanz einen fünf Sekunden gültigen
Snapshot der öffentlichen Quellen-/Pipeline-Zähler (`SnapshotCache`). Nur ein Aufruf
berechnet einen abgelaufenen Snapshot neu. Nach erfolgreich committeten Aktualisierungs-
anforderungen wird er verworfen; eine während der Abfrage erfolgte Invalidierung lässt
keinen veralteten Snapshot erneut gültig werden. Jeder Aufruf erhält eine eigene Kopie
für seine konfigurationsabhängige Darstellung. Sitzungen, Rollen, Berechtigungen und die
Aktualisierungsberechtigung werden nicht gecacht, sondern weiterhin vor jedem Lesen
frisch innerhalb der bestehenden Sicherheitstransaktion geprüft. Fehlgeschlagene
Statistikabfragen werden nicht als gültiger oder künstlich leerer Snapshot gespeichert.
