# PostgreSQL ab Phase 3

Das Projektimage `cve-postgres:18-phase23` verwendet PostgreSQL **18.6** aus der offiziellen Alpine-3.24-Basis mit Digest
`sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395`.
`gosu` wird aus festem Commit mit Go 1.27.3 und x/sys 0.44.0 neu gebaut; Quellen-/Modulhashes sind unter `infrastructure/postgres/gosu/` gesperrt.
Kein automatisches Versionsupgrade beim normalen Start. Fehlende Buildartefakte werden aus den festgelegten Inputs gebaut. Die beiden Datenbanken `cve_monitoring`
und `n8n` teilen eine Instanz; sie haben getrennte NOLOGIN-Owner und CONNECT-ACLs.
Anwendungs-DDL existiert ausschließlich in `cve_monitoring`; n8n erhält keine vorgebauten Tabellen.

## Lokaler Aufbau

Linux-Host, Docker/Compose, OpenSSL und eingerichtete `.venv` vorausgesetzt:

```bash
make setup
CVE_DOCKER_SUDO=1 make db-secrets
CVE_DOCKER_SUDO=1 make db-up
CVE_DOCKER_SUDO=1 make db-provision
CVE_DOCKER_SUDO=1 make db-migrate
CVE_DOCKER_SUDO=1 make db-check
CVE_DOCKER_SUDO=1 make db-test
CVE_DOCKER_SUDO=1 make db-down
```

Ohne erforderliches sudo die Variable weglassen. Alle Befehle beziehen sich ausschließlich
auf das validierte Compose-Projekt. Für eine abweichende Konfiguration `CVE_ENV_FILE` setzen.
`db-up` startet nur PostgreSQL, `infra-up` nur Nginx. `db-down` stoppt PostgreSQL und erhält
Daten-Bind-Mount und Credentials. Reguläre Start-/Stop-Befehle löschen keine Daten, initialisieren bestehende
Daten neu oder setzen Passwörter zurück. Nur isolierte Testprojekte mit passenden Labels
werden am Testende samt ihren eigenen Bind-Daten entfernt.

Die persistenten Daten liegen unter `MOUNT_BASE/storage/<projekt>/postgres-data`,
eingebunden auf `/var/lib/postgresql`. TLS-Dateien werden nach
`SECRETS_BASE/storage/<projekt>/postgres-tls` kopiert und read-only eingebunden.
Die Dateirechte und Eigentümer entsprechen dem PostgreSQL-Benutzer im Image.
Vorhandene alte Named Volumes werden beim ersten Start nach dem Stoppen der alten
Container übernommen; Details im [Startcontroller](start-controller.md).

`db-secrets` erzeugt nur im Development CSPRNG-Credentials und eine separate lokale CA.
Die einmaligen Dateien liegen unter `PG_WORK_DIR/<COMPOSE_PROJECT_NAME>/`: `secrets/` mit
17 getrennten Passwortdateien, `tls/` mit Servercert/-key und CA-Cert, `private/` mit CA-Key.
Secretdateien 0600/0400 und Verzeichnisse 0700; nichts davon versionieren. Wiederholtes
Generieren bestätigt vorhandene vollständige Dateien und überschreibt nichts.
CA und Leaf sind ausschließlich Entwicklungs-PKI (365 bzw. 30 Tage). Produktion benötigt
extern bereitgestellte Dateien mit denselben Namen, vertrauenswürdige CA und SAN `cve-postgres`.
Runtime-Dienste bekommen später jeweils nur ihre eigene Rolle/Secretdatei.

## Container und Netzwerk

Nur `cve_data`, keine Hostportfreigabe, kein Docker-Socket, kein Egressnetz. Rootfs read-only,
begrenzte Tmpfs-/RAM-/CPU-/PID-/Logbudgets und `no-new-privileges`. Der Startwrapper kopiert
TLS-Dateien in den privaten read-only Bind-Mount und bereitet Eigentümer vor. Ausschließlich der offizielle
Initialisierungsprozess nutzt CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID; PostgreSQL PID 1 läuft
nach gosu als UID/GID 999 ohne effektive Capabilities. Das ist mit realem `/proc/1/status` geprüft.

Das private Datenverzeichnis wird nach Vorgabe des offiziellen PostgreSQL-18-Images an
`/var/lib/postgresql` gemountet, PGDATA ist `/var/lib/postgresql/18/docker`.
Nicht nur das versionsabhängige Unterverzeichnis mounten. Ausschließlich den eigenen
projektgebundenen Bind-Pfad verwenden.
Andere Hauptversionen werden niemals automatisch migriert oder deren Daten gelöscht.

HBA erlaubt Netzwerkverbindungen nur mit TLS und SCRAM-SHA-256, getrennt je Datenbank/Rolle.
Lokale Socketwartung benötigt die OS-Identität postgres und eine explizite Peer-Zuordnung
zu postgres_admin. Kein `trust`; andere lokale Logins sind gesperrt. Operatorwerkzeuge auf
Linux verwenden die interne Container-IP als `hostaddr`, prüfen aber den TLS-Namen
`cve-postgres` mit `verify-full`. Das veröffentlicht keinen Hostport. Für entfernte Betreiber
ist ein freigegebener Wartungspfad vorzusehen; diese Werkzeuge bauen keinen SSH-Tunnel.

Die Docker-Netzgrenze ersetzt keine Host-Firewall. Ein privilegierter Hostbetreiber kann
interne IPs erreichen. Die bereits dokumentierte Produktionsvoraussetzung aus Phase 2 bleibt bestehen.

## Konfiguration und Verfügbarkeit

`postgresql.conf`, `pg_hba.conf` und `pg_ident.conf` liegen read-only vor. Unix-Socket und
TLS-Ziel liegen im Tmpfs. Zeitzone UTC, max_connections 64, shared_buffers 128 MB,
work_mem 4 MB, maintenance_work_mem 32 MB, RAM-Limit 512 MB, WAL-Limit 1 GB, Autovacuum aktiv.
WAL/Autovacuum/RAM bei realem Datenvolumen gemeinsam neu bemessen; die Werte sind ein lokaler
Ausgangspunkt. Ein Workerpool darf nicht ungeprüft 64 Verbindungen pro Dienst anlegen.
Spätere Pools erhalten kleine explizite Obergrenzen; Reserve für Migration/Wartung einplanen.

`pg_isready` meldet Instanzverfügbarkeit. `db-check` prüft zusätzlich Alembic-Head, acht Schemas
und sämtliche realen Anwendungslogins. Ein grüner Instanzhealthcheck ersetzt keine Migration.
`SELECT * FROM system.health` ist die minimale Sicht für status_probe; keine Fachzugriffsrechte.

PostgreSQL protokolliert auf stderr; Docker rotiert 3 × 10 MB. Statement-/Parameterlogging und
Fehlerstatementausgabe sind aus. Fehlerwerte sind kurze Codes statt ungefilterter SQL-Payloads.
Konfigurationsfehler mit `postgres --describe-config`, `SHOW`, `pg_settings.pending_restart`,
`pg_file_settings` und `pg_hba_file_rules` prüfen. Kein vollständiges Compose-/Env-/Auth-Dump in Tickets.
Reloadfähige Änderungen über eine lokal autorisierte Wartungsverbindung mit
`SELECT pg_reload_conf()` übernehmen; restartpflichtige Werte im Wartungsfenster ändern.
TLS-Wechsel benötigt Recreate, damit der Wrapper das neue Bundle ins Tmpfs kopiert.

## Migration und Wartung

Alembic: `database/alembic.ini`, explizite DDL unter `database/migrations/versions`.
Migrationen laufen als cve_migrator nach `SET ROLE postgres_owner`, unter transaktionalem
Advisory-Lock. Versionstabelle `public.alembic_version`. Kein ORM-create_all und keine n8n-DDL.
Ein Fehler rollt DDL und Versionsstand zurück. Wiederholung auf Head ändert keine Fachdaten.
Downgrades sind absichtlich gesperrt: gesicherten Stand isoliert wiederherstellen, prüfen,
dann Betreiber-Cutover planen. Bestehende Migrationen nach Nutzung nicht umschreiben.

Regelmäßig freien Volumeplatz, `pg_database_size`, WAL-Wachstum, `pg_stat_activity`, blockierende
Transaktionen und `pg_stat_user_tables` (dead tuples, letzte Analyze/Vacuum-Zeit) prüfen.
`ANALYZE` nach großen Importen, Autovacuum beobachten. `VACUUM FULL` blockiert und benötigt
ggf. zusätzlichen Platz; keine unbeaufsichtigte Standardwartung. Indexpläne vor Optimierungen
mit `EXPLAIN (ANALYZE, BUFFERS)` auf geeigneten Testdaten prüfen. Ein Indexbeleg mit 3000
synthetischen Snapshots ist vorhanden; kein Skalierungsversprechen für den gesamten CVE-Bestand.

Minorupdate: offiziellen Digest verifizieren, Backup+isolierten Restore erstellen, Testprojekt
mit neuem Image prüfen, Wartungsfenster und Rückkehr auf Backup planen. Majorupgrade separat:
Zielversion, Extensions/Locale, `pg_upgrade --check` oder logischer Dump/Restore und Platz prüfen;
neues isoliertes Volume, Integritäts-/Rechte-/Anwendungstests, erst danach bewusster Cutover.
Niemals einen neuen Major-Digest ungeprüft auf ein bestehendes Datenverzeichnis starten.

Runtime-Passwörter explizit rotieren: neues Credential geschützt bereitstellen, betroffenes
Service-Wartungsfenster, `db-provision --rotate` über den Modulaufruf ausführen, Pools neu laden,
alte Verbindungen beenden und reale neue Logins prüfen. Dieser Schalter rotiert alle 16 verwalteten
Anwendungslogins, nicht postgres_admin. Bei Erststart/Wiederholung niemals verwenden.
Administratorpasswort separat in einer bestehenden Wartungsverbindung ändern und Secretdatei
koordiniert ersetzen; `POSTGRES_PASSWORD_FILE` setzt es auf bestehendem Volume nicht neu.
Keine Passwortwerte als Shell-/SQL-Kommandozeilenargument. Ausfall zwischen SQL-Änderung und
Dateitausch benötigt den geschützten lokalen Peer-Wartungspfad und Betreiberabgleich.

[Backup/Restore](../operations/postgresql-backup-restore.md),
[DDL und Grenzen](../database/overview.md), [Entscheidung](../architecture/decisions/ADR-0021-postgresql-phase03.md).

Phase 23 prüft den Start des bestehenden Debian-Clusters im neuen Runtimeimage einschließlich Rollen-Credentials, Tabellenhashes und Unicode-Indexsortierung. Beide Anwendungsdatenbanken verwenden `PG_UNICODE_FAST`. Andere Anwendungslocales müssen vor einer Übernahme separat geprüft werden. Der Datenbankprozess läuft nun als unprivilegierter Alpine-Benutzer postgres (UID 70); der geprüfte Erststart passt vorhandene Datendatei-Eigentümer an. Es werden keine Datenbanken oder Credentials zurückgesetzt.

Der Phase-23-Quellbuild enthält weder XML/XSLT noch den optionalen LLVM-JIT. LLVM würde die entfernte alte XML-Bibliothek erneut einbinden. Die Datenbank nutzt weiterhin den normalen PostgreSQL-Executor; die gezielte `api_security`-Rolleneinstellung `jit=off` bleibt bestehen. Rollen-, Integritäts-, Pipeline- und Lasttests prüfen diesen Build.
