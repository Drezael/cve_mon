# PostgreSQL sichern und isoliert wiederherstellen

## Sicherungsumfang

```bash
CVE_DOCKER_SUDO=1 make db-backup BACKUP_DIR=.runtime/backups/manueller-stand-001
CVE_DOCKER_SUDO=1 make db-restore-test BACKUP_DIR=.runtime/backups/manueller-stand-001
```

Ein neues Zielverzeichnis ist Pflicht; bestehende Verzeichnisse werden nicht überschrieben.
`db-backup` ohne BACKUP_DIR erzeugt ein neues projektbezogenes Verzeichnis.
Die Ablage ist 0700, Dateien 0600. Inhalt enthält personenbezogene Daten und geschützte
Credentials/Verifikatoren; Zugriff, verschlüsselte externe Ablage und Aufbewahrung betreiberseitig
beschränken. Backups niemals ins Git oder als Testartefakt öffentlich hochladen.

Enthalten sind zwei Custom-Dumps (`cve_monitoring.dump`, `n8n.dump`), Globals ohne
Rollenpasswortverifikatoren, Metadaten und SHA-256-Manifest. Die Dumps sichern Tabellen, Inhalte,
Schemas, Indizes, Constraints, Policies, Funktionen, Eigentümer, ACLs und Alembic-Version.
Metadaten erfassen Rollenattribute, Konfiguration, Tabellenfingerprints und semantischen
Katalogzustand. Jede Datenbank wird mit einem konsistenten MVCC-Snapshot gesichert.
Zwischen zwei getrennten Dumps/Fingerprintabfragen besteht kein atomarer Clustersnapshot:
für einen deterministischen Gesamtstand Fachschreiber und n8n vor dem Backup quieszieren,
Migrationen währenddessen sperren. Bei laufenden Schreibern kann die Restoreprüfung berechtigt
abweichende Fingerprints melden. Die Funktion behauptet keine clusterweite PITR-Sicherung.

Separat geschützt sichern und verfügbar halten: Rollenpasswörter bzw. kontrollierte neue
Credentials, MFA-Verschlüsselungsschlüssel mit key_id-Zuordnung, später den n8n-Encryption-Key,
produktive TLS-/CA-Abhängigkeiten und Deploymentkonfiguration. Das Datenbankbackup allein
kann verschlüsselte TOTP-/n8n-Daten nicht entschlüsseln. Keine entschlüsselten MFA-Seeds im Dump.

## Wiederherstellung

`db-restore-test` akzeptiert ausschließlich eine vollständige, unveränderte Sicherung der
unterstützten Hauptversion. Er erzeugt selbst ein neues zufälliges Compose-Testprojekt,
separates Volume, neue TLS-Dateien und neue Rollenpasswörter; ein Produktivziel kann nicht
angegeben werden. Neue Credentials sind absichtlich unabhängig vom alten Cluster.

Ablauf: Manifest prüfen, leere Instanz starten, bekannte Owner/Logins provisionieren,
Custom-Dumps mit `pg_restore --exit-on-error` einlesen, Tabellenfingerprints, Alembic-Head,
Rollenattribute, Eigentümer, Objekt-ACLs, Constraints, Indizes, Policies und Funktionen vergleichen,
alle Anwendungslogins mit TLS erneut prüfen. `globals.sql` ist eine zusätzliche Betreiberreferenz,
kein ungeprüft gegen beliebige bestehende Cluster ausgeführtes Skript. Die bekannte Rollenstruktur
wird kontrolliert provisioniert und anschließend verglichen. Testprojekt und sein eigenes Volume
werden auch bei Fehlern entfernt; Diagnosen und Secretdateien verbleiben geschützt in `.runtime`.

Der automatisierte Test stoppt die Quelle nach dem Backup, stellt ohne Quellzugriff wieder her
und vergleicht unter anderem Server/Gruppen, Inventare, CVEs, Findings, Konten, Sessions, MFA,
Recovery-/Accountverifikatoren, Jobs, Outbox, Audit, Präferenzen und synthetische n8n-Daten.
Das ist ein tatsächlicher Restore, kein ausschließliches Auflisten des Dumpinhalts.
Manipulierte Dumpdateien werden bereits vor dem Erzeugen einer Zielinstanz abgewiesen.
Das Manifest erkennt versehentliche Veränderung; es ist keine Signatur gegen einen Angreifer,
der Dump und Manifest gemeinsam ersetzen kann. Sicherungsquelle muss vertrauenswürdig sein.

Produktiver Wiederanlauf ist ein eigener geplanter Betreiber-Cutover: geprüfte Zielinstanz
aufbauen, externe Schlüssel wieder zuordnen, Anwendungstests, Secret-/Verbindungswechsel und
Rollbackpunkt festlegen. Dieses Werkzeug überschreibt niemals bestehende Produktivdaten.
Kapazitäts-/RPO-/RTO- und PITR/WAL-Archivierungstests folgen in der Betriebsphase.

## Fehlerbehandlung

Fehlendes sudo/Dockerrecht: freigegebenen Operatorzugang verwenden, keine Docker-Socket-Rechte
global öffnen. Fehlende Secretdatei oder falsche Rechte: ursprüngliche geschützte Ablage
bereitstellen; nicht löschen/neu generieren, solange das alte Volume verwendet wird.
Healthcheck grün, Migration rot: `db-migrate`, sicheren Fehlercode und Versionsstand prüfen;
kein `down -v`. Major-Datenverzeichnisfehler: Image-/PGDATA-Zuordnung prüfen, Backup isoliert
testen; niemals Datenverzeichnis entfernen. Timeout/Locks: blockierende Transaktion in einem
Wartungskontext identifizieren; keine pauschalen Prozess-/Volume-Löschaktionen.
