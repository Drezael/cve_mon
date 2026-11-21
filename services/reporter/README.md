# cve-reporter – technische Vorbereitung

Dieser Worker wird in Phase 6 nicht gestartet. Keine Jobs, Polling-Loops oder
Fachverarbeitung implementiert. Spätere Laufzeit verwendet das installierte Paket
`cve_common` (0.6.0), `ServiceSettings` mit eigenem `CVE_SERVICE_`-Prozesspräfix,
`Resources` und `run_worker(settings, stop_event, signals=True)`.

Vorgesehene PostgreSQL-Identität: `reporter` mit eigenem privaten Passwortfile und
CA. Kein Superuser, kein automatisches SET ROLE, keine Erweiterung der Phase-3-Rechte.
Ein Kontext/Task erhält eine eigene Session; Commit nur mit `transaction()`.
Nur benötigte Netze aktivieren: cve_data, ggf. cve_internal und für ausdrücklich
freigegebenen HTTP-Egress cve_egress_internal. Externe HTTP-Aufrufe über HTTPX mit
explizitem Envoy-Proxy, geprüftem TLS und konfigurierten Zielnamen. Keine frei
gewählten Identitätsheader als Authentifizierung verwenden.

[Technische Architektur](../../docs/architecture/python-services.md),
[Übergabe](../../docs/development/phase-06-handover.md).
