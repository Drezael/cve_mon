# Secretrotation Phase 23

Kompromittierten Scope identifizieren, Sitzungen/Tokens sperren, neue unabhängige Schlüssel privat provisionieren, Dual-Key-/Key-ID-Kompatibilität prüfen, referenzierte Daten kontrolliert reencrypten, Funktionsprobe durchführen, Altwert widerrufen, Audit/Backups nachführen. Keine Produktivwerte in Tests kopieren. n8n-Credentials verlangen ihren ursprünglichen Encryption-Key oder explizite Reencryption. MFA- und HMAC-Rotation erfordern passende Verfahren der bestehenden Auth-/Uploaddokumentation. Backupschlüsselwechsel erzeugt einen neuen getrennten Backupzyklus; alte Archive benötigen ihren bisherigen Schlüssel.

## Persönliche Ansible-Vaults

Die Befehle aus dem Repository mit der expliziten Umgebung des betreffenden Projekts
aufrufen. `python` bezeichnet dessen eingerichtete `.venv/bin/python`:

```sh
python -m scripts.automation_executor.rotation stage --key-id rotation-2026-11
python -m scripts.automation_executor.rotation rewrap
python -m scripts.automation_executor.rotation verify
python -m scripts.automation_executor.rotation retire --key-id 1 --backup-keyring /privates-backuparchiv/ssh-keys-vor-rotation.json
```

`stage` verteilt beide Entschlüsselungsschlüssel, bevor der aktive Schreibschlüssel
wechselt. Neue API-Anfragen und neue Executorläufe laden den Keyring erneut;
ein laufender Executor behält seine bereits entschlüsselte Anfrage. Dateiersetzung
ist atomar. `rewrap` bestätigt jede neue Hülle vor dem Commit und verarbeitet
höchstens 100 gesperrte Vaults pro Transaktion. Ein Wiederanlauf überspringt bereits
migrierte Vaults; Passwort- und SSH-Feldhüllen bleiben erhalten. `verify` prüft alle
Vault-Hüllen und verweigert den Abschluss bei alten Referenzen, einschließlich
Legacy-Profilen. Solche Profile müssen zuvor mit dem persönlichen Vault neu
konfiguriert oder nach dem vorgesehenen Löschverfahren entfernt werden.

`retire` entfernt ausschließlich einen inaktiven Schlüssel nach erfolgreicher Prüfung.
Zuvor schreibt beziehungsweise prüft er einen privaten archivierten Keyring. Das
Archiv zusammen mit allen älteren Datenbanksicherungen aufbewahren: Ein Restore
eines alten Backups braucht dessen damaligen Laufzeitschlüssel. Ein Restoretest muss
mit der archivierten Hülle und dem dazugehörigen Keyring erfolgen, bevor dessen
letzte Archivkopie nach der Backup-Aufbewahrungsfrist gelöscht werden darf.
Die Rotation selbst löscht keine Schlüsselarchive oder Backups.
