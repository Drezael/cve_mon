# Postfix-Queue, Backup und Wiederherstellung

Die einzige Transportqueue liegt im Bind-Mount `MOUNT_BASE/storage/<projekt>/postfix-queue` unter
`/var/spool/postfix`. Stop/Start und Recreate erhalten angenommene Nachrichten.
4xx, Verbindungsfehler, TLS-/AUTH-Fehler führen zu nativen begrenzten Wiederholungen.
5xx bei einem Empfänger erzeugt eine native Unzustellbarkeitsnachricht mit leerem
Envelope-Sender; keine Rückläuferkopie des Originals (`bounce_size_limit=1`, native Rückgabe ausschließlich der Header).
Bounces gehen ausschließlich über denselben gesicherten Relaypfad, nicht per lokaler
oder MX-Zustellung. Bounces bleiben höchstens einen Tag, Originale höchstens fünf Tage.
SMTP besitzt keine Exactly-once-Garantie: Verbindungsabbruch nach DATA vor 250 kann
beim Retry ein Duplikat erzeugen. Fachliche Ereignis-ID später im Notification-Service
führen; keine eigene Zustellqueue in Python implementieren.

```bash
CVE_DOCKER_SUDO=1 make mail-backup BACKUP_DIR=/sicherer/pfad/neues-backup
# Dienst bleibt nach konsistentem Backup gestoppt.
CVE_DOCKER_SUDO=1 make mail-up
# Restore nur in eigene gestoppte LEERE Queue, nie über angenommene Nachrichten:
CVE_DOCKER_SUDO=1 make mail-restore BACKUP_DIR=/sicherer/pfad/neues-backup
CVE_DOCKER_SUDO=1 make mail-up mail-check
```

Backup stoppt ausschließlich den eigenen Postfix. Ein offline Netzwerk-none-Helfer
liest den Bind-Mount; das Hostprogramm schreibt Archiv 0600 und Manifest 0600 im
Verzeichnis 0700. Manifest enthält Imageversion und SHA256. Keine Livekopie.
Extern separat sichern: Policies, CA-Trust, Zertifikate/Schlüssel, Providercredentials,
Build-Lock. Archiv enthält vertrauliche Nachrichten: verschlüsselt außerhalb des Hosts
aufbewahren, Zugriff begrenzen, Aufbewahrung/Löschung nach Betriebsrichtlinie.
Der Helfer bietet keine Verschlüsselung; hierfür einen freigegebenen verschlüsselten
Backup-Zielpfad verwenden. Nicht in Git oder allgemeine CI-Artefakte hochladen.

Restore prüft Hash, Imageversion, private Archivmode und sichere Tar-Mitgliedspfade;
lehnt laufenden Dienst sowie jede vorhandene reguläre Queue-Datei ab. Wiederherstellung
in einem frischen eigenen Bind-Verzeichnis oder isoliertem Ersatzprojekt durchführen, Netzwerk zunächst
geschlossen, Policies/Secrets getrennt wiederherstellen, dann `mail-up`. Native numerische
Eigentümer bleiben erhalten. Vor Freigabe Queue prüfen; keine Massenzustellung durch
unüberlegtes `mail-flush`. Niemals `down -v`, Volume-RM oder postsuper auf Produktivqueues
als Reparatur verwenden. Der Integrationstest löscht nur seine eigens markierten Testdaten.

Kapazitätsalarm: Queue-Anzahl/-Alter, Deferred-DSNs, freien Speicher und Health separat
beobachten. Bei vollem oder nicht beschreibbarem Volume keine weiteren 250-Annahmen;
Speicher bereitstellen, Dateirechte/Bind-Verzeichnis prüfen, anschließend Recovery verifizieren.
Externer Ausfall allein macht die lokal schreibbare Queue nicht ungesund.
