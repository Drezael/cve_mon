# Übergabe an Phase 23

Statusdaten gehören zum Schema status; Katalog und Probes sind codeeigen in cve_api.status. Betriebseinstellungen liegen im vorhandenen API-Settingskontext; lokale Adapter unter infrastructure/status. Verträge unter contracts/status und contracts/api/status.openapi.json. Frontend bleibt services/dashboard.

Phase 23 übernimmt das übergreifende Security Hardening und Lastoptimierung, Phase 24 die endgültige Produktionsfreigabe. Es gibt keinen externen unabhängigen Beobachtungspunkt und keine öffentlichen Diagnosen. Quellfristen müssen ausdrücklich in status.source_expectations genehmigt werden; ohne diese erscheint unknown. Envoyreadiness ist kein Nachweis externer Ende-zu-Ende-Verfügbarkeit. Keine automatischen Reparaturen ergänzen. Bei einer weiteren kompatiblen Migration die kontrollierte Migrationsbereitschaft in status.sample prüfen.

Rollback: vorheriges API-/Notification-Image und statischen Build aktivieren; additive Statusdaten dürfen bestehen bleiben. Kein destruktives Downgrade; geprüften Backup-/Restoreweg verwenden. Alle Phase-22-Abnahmeprüfungen sind abgeschlossen; Nachweise und betriebliche Grenzen stehen im [Abnahmebericht](phase-22-acceptance.md).
