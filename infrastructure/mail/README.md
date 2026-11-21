# Native Postfix-Laufzeit

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


`main.cf` und `master.cf` definieren native SMTP-/Queue-Dienste. `runtime.py`
validiert Schlüssel, generiert native Maps auf tmpfs, wartet auf die eigene
Namespace-Bootbindung und redigiert Logs. Keine SMTP-/Zustelllogik in Python.
Der Paket-Lock ist vor jedem Offline-Build per SHA256 geprüft.

[Bereitstellung und Befehle](../../docs/deployment/postfix.md),
[Sicherheitsarchitektur](../../docs/security/postfix-security.md),
[Queue/Recovery](../../docs/operations/postfix-backup-restore.md).
Updates: neuen Basisdigest/Paket-Lock aus signierten offiziellen Alpine-Quellen
prüfen, Version in Image/Compose/Validator/Clientausnahme gemeinsam aktualisieren,
volle Regression einschließlich Restore ausführen. Keine gleitenden Image-Tags.

Phase 23 verwendet Postfix 3.11.7 auf der gepinnten Python-3.12-/Alpine-3.24-Basis. Alle APKs sind im Lock mit URL und SHA256 erfasst und werden beim netzlosen Build zusätzlich anhand der Alpine-Paketsignaturen geprüft. Der Betriebspfad und die native SMTP-/Queue-Semantik bleiben unverändert.
