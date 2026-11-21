# Wiederherstellung nach Containerverlust

Mit vorhandenem Queue-Bind-Mount `make mail-up`: neue Laufzeitmaps/Guard, identische
Queue weiterverarbeiten. Nach Host-/Daemon-Restart ebenfalls Mailoperator verwenden.
Bei Verlust des Bind-Verzeichnisses konsistentes vertrauliches Backup in ein leeres eigenes Bind-Verzeichnis
wiederherstellen. Version/Hash und native Dateieigentümer prüfen, Konfiguration und
Secrets separat bereitstellen, anschließend Freigabe und kontrollierte Zustellprobe.
[Ausführbares Backup-/Restore-Verfahren](postfix-backup-restore.md).
