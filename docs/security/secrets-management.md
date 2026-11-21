# Secrets-Lebenszyklus Phase 23

Inventar: getrennte PostgreSQL-Rollenpasswörter, TOTP-Verschlüsselungsschlüssel/Key-ID, Passwort-/Tokenverifikatoren, Gateway-/Probe-/HMAC-Schlüssel, TLS-Privatekeys, n8n-Encryption-Key, SMTP-Credentials und separater Backupschlüssel. Private Werte bleiben in bestehenden projektspezifischen Runtimeverzeichnissen, reguläre Dateien mit 0400/0600 und restriktiven Eltern. Keine finalen Symlinks, unbeschränkten Reads oder Klartext-Env-Buildargs.

Logs/Fehler enthalten keine Credentials, Rohinventare, Mailadressen oder privaten Schlüssel. CI lädt ausschließlich minimierte Phase-23-Berichte/SBOMs hoch; keine .runtime-Verzeichnisse pauschal. Sourceprovenienz speichert Hashes und keine Umgebungswerte. Secret-Scan erhält die bestehende unveränderte Baseline.

Bestehende Schlüssel werden nicht zurückgesetzt. Rotation: neuen Schlüssel separat provisionieren, kompatible Übergangsphase testen, referenzierte Daten mit passender Key-ID migrieren, Widerruf nach erfolgreicher Probe, Audit und Backups sichern. n8n-Key darf nicht ohne Credential-Reencryption ersetzt werden. Backupschlüssel wird separat verwahrt und nie mit dem verschlüsselten Export veröffentlicht.
