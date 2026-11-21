# Restoreprüfung Phase 23

make recovery-test erstellt echte logische Dumps beider Datenbanken, verschlüsselt jeden Sicherungsbestandteil, entfernt die Klartextquelle, entschlüsselt in einen neuen privaten Pfad und ruft den bestehenden vollständigen Restore in einem separaten cve-db-restore-Projekt auf. Tabellenfingerprints, Rollen-/Schema-/Katalogmetadaten werden nativ verglichen. Die Ausgangsinstanz wird nicht überschrieben.

Zusätzlich beschädigte/trunkierte/falschgeschlüsselte Umschläge werden vor Veröffentlichung abgewiesen. Der vorhandene Backup-Prüfsummenfehler wird weiterhin getestet. Der ENOSPC-Fall nutzt nur einen Tablespace im begrenzten/tmp-tmpfs einer eigenen PostgreSQL-Testinstanz; der Insert muss mit DiskFull scheitern und0 Zeilen hinterlassen. Weder Hostdisk noch normale Datenbank werden gefüllt.

RPO ist der Zeitpunkt der je Datenbank konsistenten logischen Dumps; kein WAL/PITR-Versprechen und keine verteilte Transaktion zwischen Datenbanken. Gemessene lokale Restorezeit ist keine Produktions-RTO; Schlüsselbeschaffung, Erkennung, Datentransfer und Freigabe kommen hinzu. Rohbericht phase-23-recovery.json.
