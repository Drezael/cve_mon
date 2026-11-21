# Installation, Releases und Wiederherstellung

Phase 24 verwendet die bestehende Compose-Plattform mit 13 Diensten. Alle Befehle
werden im Repository mit eingerichteter `.venv` ausgeführt. Auf diesem Host ist
`CVE_DOCKER_SUDO=1` erforderlich. Docker-Zugriff gehört ausschließlich zum Operator;
kein Plattformcontainer erhält den Socket. Der Operator benötigt die zum Manifest
passende Quellkopie: jede Änderung am Checkout wird vor dem Start abgewiesen.

## Release erzeugen und transportieren

`scripts/deployment/build.py` verwendet die vorhandenen gesperrten Runtime- und
Servicebuilder sowie `npm ci` mit Lockdatei. `SOURCE_DATE_EPOCH` stammt aus Git.
Der Build startet keine Dienste. Er benötigt die dokumentierten Compiler,
Scanner und Downloadquellen; für eine abgeschottete Installation wird anschließend
mit den erzeugten Images gearbeitet. Ein vollständiger kalter Neubau ist kein
Versprechen identischer Imagebytes über unterschiedliche Buildhosts hinweg.

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage build
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage release \
  --version 0.24.0-rc.1 --bundle .runtime/releases/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage export-images \
  --bundle .runtime/releases/rc1 --directory .runtime/releases/rc1-images
```

Jedes Ziel muss neu sein. Das Manifest enthält Dateihashes der Quellen, des
gebauten Frontends und der SBOM-/Scan-/Testnachweise, 13 unveränderliche Image-IDs
und deren geprüfte Konfigurationsdigests, Schemahead und Konfigurationsversion.
Die Release-ID ist der Hash des kanonischen Inhalts; das separate Buildprotokoll
enthält den tatsächlichen Erstellungszeitpunkt. Wiederholte Verpackung gleicher
Eingaben liefert dieselbe Inhaltsidentität. Scannergebnisse dürfen höchstens
24 Stunden alt sein und müssen exakt zu den Buildquellen passen. Ein Exportindex
bindet jedes Dockerarchiv per SHA-256. Beim Import werden zunächst **alle** Archive
auf Identität, Pfade und unerlaubte Tags geprüft, erst danach lädt Docker sie.

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage import-images \
  --bundle .runtime/releases/rc1 --directory .runtime/releases/rc1-images
```

Es findet weder ein Registry-Push noch ein automatischer Git-Commit statt.
Ohne existierenden sauberen Git-Stand ist das Ergebnis ausdrücklich ein
Entwicklungskandidat (`git_commit=null`, `production_eligible=false`). Ein
Quellhash ersetzt den für die formale Freigabe geforderten Git-Bezug nicht.
Das aktuelle Repository hat noch keinen initialen Commit. Ein Commit benötigt
nach DEP-104 einen ausdrücklichen Auftrag.

## Isolierte Erstinstallation

```bash
.venv/bin/python -m scripts.deployment.manage stage --directory .runtime/stage/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage prepare \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage preflight --bootstrap \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage deploy \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage smoke \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1
```

`stage` erzeugt nur einen neuen Vertrag mit eigenem Projektnamen und Loopbackports.
`prepare` erzeugt ausschließlich isolierte DB-Credentials und Test-PKI. Bootstrap-
Preflight prüft deshalb noch nicht alle später gerenderten Bindmounts. Der normale
Preflight prüft auch diese. Die Reihenfolge ist PostgreSQL, Rollen, Migration,
Anwendungskonfiguration, kontrollierter Envoy mit gebundenen Clientnamespaces,
Mail und Worker/API/n8n, importierte Workflows und Nginx. Der Head ist
`00031_hardening_list_projection`; bereits laufende Dienste migrieren nicht selbst.
Der Smoke prüft alle 13 Gesundheitszustände, Imageidentitäten, echte DB-Logins,
HTTPS 200/401/404 und Egressbindungen. Er ist ausdrücklich keine fachliche Abnahme.

Ein abgeschlossener identischer Rollout prüft erneut, erzeugt aber weder neue
Container noch ein neues Journal. Ein exklusives Lock verhindert parallele
Operatorläufe; ein Hashjournal dokumentiert Übergänge und Fehler. Ein fehlgeschlagener
Preflight blockiert vor Dienständerungen. Vorhandene gestoppte Container oder
Volumes gelten nicht als frische Installation; eine nicht erreichbare bestehende
Datenbank muss zuerst kontrolliert wiederhergestellt und gesichert werden. Nach späteren Fehlern bleiben Volumes
zur Diagnose erhalten. Kein automatisches `down -v`, kein globales Docker-Prune.

Der erste Administrator wird anschließend explizit mit dem vorhandenen Werkzeug
angelegt: [Erstadministrator](../operations/initial-administrator.md).
Dabei `CVE_ENV_FILE` auf die eigene `platform.env` setzen. Passwort verdeckt
interaktiv oder aus privater Passwortdatei; danach MFA einrichten. Es gibt
keinen Defaultbenutzer, keinen öffentlichen Bootstrap und keine Testdaten beim
gewöhnlichen Deployment. Die native Testkampagne initialisiert nur ihre eigene
synthetische Identität und ausschließlich kontrollierte Datenquellen/Testempfänger.

## Umgebungen und Secrets

Der verbindliche Vertrag ist [configuration.schema.json](../../configuration/deployment/config/configuration.schema.json).
`env_file` verweist auf die bekannte, streng geprüfte KEY=value-Konfiguration;
`name`, `kind`, Ressourcenuntergrenzen und Zertifikatsrestlaufzeit sind Pflicht.
Entwicklung, Integration und Staging binden nur Loopback. Integration/Staging
benötigen einen eigenen `cve-db-test-phase24-*` oder `cve-db-test-release-*` Namen.
Produktion benötigt `APP_ENV=production`, eigene PKI/Secrets und einen extern
bereitgestellten Ed25519-Verifikationsschlüssel. Beispiele stehen in
[Stagingbeispiel](../../configuration/deployment/config/examples/staging.json). Sie sind Vorlagen und
starten nichts. Ressourcenuntergrenzen sind Startbedingungen, keine Lastzusagen.

DB-Rollenpasswörter, TLS-/mTLS-Schlüssel, MFA-Keyring, Session-/Tokenmaterial,
Service-HMAC-Schlüssel, Postfix-Zugang und n8n-Verschlüsselungsschlüssel bleiben
in privaten projektbezogenen Dateien unter `.runtime`; sichere externe
Bereitstellung für Produktion ist Betreiberaufgabe. `prepare` validiert dort nur
das vollständig extern bereitgestellte Material und erzeugt keine Schlüssel.
Schlüsseldateien benötigen
0600 und dürfen keine Symlinks sein. Öffentliche Verträge enthalten nur Pfade.
Diagnoseausgaben dürfen keine Konfigurationsinhalte/Passwörter/Token ausgeben.
Es erfolgt keine automatische Rotation bestehender Schlüssel. Nach Restore
müssen n8n-Credentials tatsächlich entschlüsselt werden können, nicht nur als
Zeilen vorhanden sein. [Rotation](../operations/secret-rotation.md),
[Zertifikate](../operations/certificate-rotation.md),
[Tokenrotation](../operations/inventory-credential-rotation.md).

## Backup und Restore

Für den extern aufzubewahrenden Backupschlüssel eine private Datei mit dem
Base64-kodierten Wert von 32 zufälligen Bytes nach dem vorhandenen
[Backupverfahren](../operations/backup-security.md) bereitstellen. Sie darf
nicht im Sicherungsverzeichnis liegen. Schlüssel separat/offsite hinterlegen;
ohne Schlüssel gibt es keine Wiederherstellung. Keinen Schlüssel in Shellargumente,
Git, Berichte oder Tickets kopieren.

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage backup \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1 \
  --backup .runtime/backups/rc1 --key-file /secure/offline-backup.key
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage restore-test \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1 \
  --backup .runtime/backups/rc1 --key-file /secure/offline-backup.key
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.deployment.manage recover \
  --environment .runtime/stage/rc1/environment.json --bundle .runtime/releases/rc1 \
  --backup .runtime/backups/rc1 --key-file /secure/offline-backup.key \
  --directory .runtime/stage/recovered-rc1
```

Backup hält schreibende APIs/Worker/n8n und Postfix kontrolliert an, sichert beide
Datenbanken logisch, Rolleneigenschaften und Rolleneinstellungen, vollständiges
Schlüssel-/PKI-/n8n-Material und die gestoppte Queue. Danach starten die Dienste
mit ihren vorhandenen Guards wieder. Chiffrierte Einzelobjekte und ein ebenfalls
chiffrierter Index verwenden die authentifizierte Phase-23-Verschlüsselung.
Ursprüngliche Datei-/Verzeichnisrechte werden im verschlüsselten Index mitgesichert.
Klartext bleibt bis zum Restore privat; nur geprüfte Konfigurationspfade erhalten
ihre ursprünglichen Rechte zurück. Weltweit schreibbare oder besondere Rechte
werden abgewiesen, private Schlüssel bleiben privat.
Temporärer Klartext wird entfernt, die privaten Archive und Schlüssel bleiben
erhalten. Backup ohne nachgewiesenen isolierten Restore reicht vor Update nicht.

Restoretest erstellt ausschließlich einen neuen isolierten DB-Cluster. Vollrestore
erstellt zusätzlich alle 13 Dienste in einem **neuen leeren Projekt**. Datenfingerprints,
Eigentümer, ACLs, Policies, Rollenattribute/-einstellungen und Schema werden vor
dem Start verglichen. Bei n8n wird allein die bekannte PostgreSQL-Darstellungs-
äquivalenz von `varchar`-Literalarrays zu `text[]` normalisiert; Werte, Operatoren,
Längenbeschränkungen und sämtliche übrige Metadaten bleiben strikt. Der native
Test prüft anschließend beide entschlüsselten n8n-Credentials im Container und
beseitigt den temporären Export. Produktion darf nicht in gewöhnliches Staging
restauriert werden. Produktivrecovery benötigt einen separaten leeren
Produktionsvertrag und eine eigens dafür signierte Freigabe.

RPO ist der letzte konsistente angehaltene logische Snapshot, ohne PITR-Zusage.
Gemessene lokale Wiederherstellungsdauer steht im Maschinenbericht; sie ist kein
Produktions-RTO. Betreiber müssen Offsite-Transfer, Schlüsselverlust, reale
Datenmenge, Verantwortliche und Wiederanlaufziel gesondert testen/festlegen.

## Update, Abbruch und Rollback

Vor jedem Update: neuen Kandidaten bauen/scannen, isoliert abnehmen, Backup und
Restoretest ausführen. Der Backupnachweis muss zur Umgebung und zum verschlüsselten
Index gehören und höchstens 24 Stunden alt sein. Für geänderte DB-Heads ist ein
geprüfter Plan mit `schema_version`, `current`, `target`, `strategy` und
`revision_sha256` **aller** Vorwärtsrevisionen Pflicht. `strategy=expand` verlangt
belegte Rückwärtskompatibilität; `restore_required` verlangt Wiederherstellung
anstelle einer pauschalen Rückmigration. Änderungen am Plan ändern den
Umgebungshash und entwerten alte Freigaben. Alembic verwendet den bestehenden
PostgreSQL-Advisory-Lock. Unbekannte Heads, Zweige und Downgrades werden abgewiesen.

Für ein reines Artefaktrollback den vorherigen geprüften Bundle und den zugehörigen
Vertrag verwenden, nur wenn dessen Code zum aktuellen Schema kompatibel ist.
Bei irreversiblen Änderungen den alten vollständigen Snapshot in ein neues leeres
Projekt restaurieren; niemals über laufende Daten restaurieren. Erst nach
Daten-/Berechtigungs-/fachlichem Nachweis separat freigegebenen Ingress-Cutover
vornehmen. Ein abgebrochener Lauf ist `blocked`, `recovery_required` oder
`rollback_required`; Ursache und Journal prüfen, bevor ein neuer Lauf erfolgt.
Alle alten Images, Backups und Volumes bis zur bestätigten Abnahme aufbewahren.

## Produktionsfreigabe und Cutover

Produktivaktionen werden ohne sauberen Git-Release und unabhängige Ed25519-
Freigabe abgewiesen. Der Betreiber hinterlegt den öffentlichen Vertrauensschlüssel
außerhalb des Bundles (nicht für andere Benutzer schreibbar). Der private
Freigabeschlüssel gehört nicht auf den Deploymenthost. Ein privater JSON-Umschlag
enthält `payload` und Base64-`signature`; signiert werden die kanonischen JSONbytes
von `payload` gemäß `contracts.canonical`. Pflichtfelder:
`release_id`, `environment`, `staging_sha256`, `action`, `expires_at`, `operator`,
`ticket`. Der Umgebungswert bindet die genaue Konfiguration, `staging_sha256`
den kanonischen Hash eines ausdrücklich akzeptierten Stagingberichts.
Freigaben laufen spätestens nach 24 Stunden ab. `action` ist genau `deploy`,
`backup`, `restore-test`, `restart-services` oder für vollständiges Recovery
`recover:<Ursprungsumgebungshash>:<SHA256 des index.enc>`.
Ein Journalstatus `approved` ersetzt keine Signatur und keinen Auftrag.

Der Deploymentbefehl benötigt dann zusätzlich `--approval <private.json>` und
`--staging-evidence <private.json>`. Die Signatur allein ersetzt keine Prüfung
aller G24-Gates. Erst nach deren Freigabe: Wartungsfenster ankündigen, Aufnahmen
und Mail kontrolliert begrenzen, Sicherung verifizieren, deployen, technische
und fachliche Nachweise prüfen, Ingress kontrolliert umschalten. Vollsync und
echte Benachrichtigungen bleiben bis zur separaten bewussten Aktivierung gesperrt.
Es ist kein Produktivziel benannt und keine Produktivfreigabe erteilt.
