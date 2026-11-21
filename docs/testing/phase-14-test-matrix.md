# Testmatrix Phase 14

`make inventory-processor-check`: Ruff, Mypy und normale Unitprüfungen.
`make inventory-processor-integration`: reale isolierte PostgreSQL-/API-/Worker-/Containerfälle.
Alle Fixtures verwenden ausschließlich eigene UUID-Composeprojekte und entfernen diese
im finally-Block. Keine geteilten fachlichen Entwicklungsdaten oder Zielserver.

| Bereich | Nachweis |
|---|---|
| Eingangsvertrag, Raw-/Canonical-SHA, JSONB, Schema, IDs, Provenienz, Zeit | test_normalization.py, parametrisiert manipulierte Metadaten |
| Debian-Epoch/Revision, RPM-EVR und Sonderzeichen | test_versions, test_bad_versions |
| Mehrfachversionen/Architekturen/Quellpakete | test_parallel_versions_architectures_and_source |
| Historische Dienst-/Container-/Imagezustände und Verweise | Normalisierungs- und E2E-Snapshotprüfungen |
| Dockerbereich und Gesamterfassungsqualität | test_collection_quality, test_no_complete_current_from_incomplete_collection |
| Optionale 1.0-Bereiche und leere erfolgreiche Listen | test_v1_optional_sections_and_empty_packages |
| Ressourcenbegrenzter Spawnprozess | test_resource_bounded_subprocess |
| Echte Annahme, Job, Snapshot, Audit/Outbox, Idempotenz | test_e2e_immutable_snapshot_and_outbox |
| Beide Uploadwege, gleiche Fachidentität, unabhängige Provenienz | test_both_sources_share_one_snapshot_and_preserve_receipt |
| Neu/alt/partial/future/gleiche Zeit/1–4 Worker | test_current_history_and_global_identity |
| Native Versiegelung einschließlich Owner und nachträglichem INSERT | test_sealed_rows_deny_owner_mutation |
| Rollenrechte und echte verweigerte SQL-Schreiboperationen | test_native_permissions, test_native_write_denied |
| Vor Archivierung angenommen, danach historisch verarbeitet | test_archive_historical_and_no_current |
| Fehlende Zuordnung und wiederholter Backfill | test_backfill_idempotent |
| Rollback nach bereits begonnenen Kindwrites und verlorene Fence | test_rollback_and_stale_fence |
| Timeout-Retry bis zur Erschöpfung, terminales Fehlerereignis | test_retry_exhaustion_and_failed_event |
| Dauerhafter Validierungsfehler ohne Endlosretry | test_permanent_rejection |
| 10.000 Pakete plus je 600 Container und Images, Bulk und Versionserhalt | test_large_package_inventory, XML-Property mit Dauer |
| Reales Wheel/Container, Health, kein Hostport/Egress/Socket | test_runtime_container_recovery_and_isolation |
| Echter PostgreSQL-Stopp/Neustart und SIGKILL/Neustart des Workers | test_runtime_container_recovery_and_isolation |
| Kollidierende Legacy-ID, native Zuordnungsprüfung, verifizierter Pointer vor Legacy-View | test_legacy_identity_collision_rejected, test_current_pointer_precedes_unvalidated_legacy_view |
| Annahme-Pendingmetriken nach Verarbeitung | test_acceptance_metrics_reflect_processing |
| Unveränderte Altmigrationen und Backup/Restore | Datenbanksuite und test_populated_snapshot_backup_restore einschließlich vollständigem Inhalts-/Katalogvergleich |
| Generische Job-/Lease-/Dispatcherfehler | vollständige Phase-7-Automationssuite |
| Ansible-Receiptkompatibilität und bestehende Uploads | vollständige Phase-11/12/13-Uploadsuite |

Die zugeschnittenen Makeziele security, concurrency, performance und e2e wählen echte
Teilbereiche derselben isolierten Suite aus. Die Gesamtabnahme führt die gesamte Suite aus.
Keine pauschalen Erfolgsannahmen aus Mocktests; Native Tests verwenden die tatsächlichen
Rollen, TLS-/mTLS-Annahme und PostgreSQL-Funktionen.
