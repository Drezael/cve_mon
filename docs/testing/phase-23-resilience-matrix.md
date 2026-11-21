# Phase-23-Resilienzmatrix

| Grenze | Fälle | Ausführbarer Nachweis |
|---|---|---|
| Transaktion/Lease | Crash vor/nach Commit, verspäteter Worker, Fencing, Duplicate | tests/automation + Fachpipelines |
| Persistenz | Neustart/Recreate/Restore beider DBs | tests/database + hardening/test_recovery |
| Platzerschöpfung | realer begrenzter tmpfs-Tablespace, atomarer Rollback | hardening/test_recovery |
| Transporte | Envoy/DNS/SMTP/n8n/PG/API/Nginx-Ausfall und Wiederanlauf | infrastructure/envoy/mail/status/runtime |
| Status | veraltete/fehlende Daten, Recoveryhysterese, Maintenance, keine falsche Entwarnung | tests/status |
| Secrets/Backups | synthetischer Leak, falscher Key, Tamper/Truncation, Restore ohne Klartextquelle | standard Secret-Test + hardening/test_controls/recovery |

Alle Störungen verwenden ausschließlich eigene Laborprojekte. Keine Hostdiskfüllung, fremden Container, realen Empfänger oder Zielserver.
