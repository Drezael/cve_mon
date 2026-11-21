# Übergabe an Phasen 12, 13 und 14

Phase 12 erzeugt im vorhandenen externen Ansible-Projekt schema-konforme Inventare aus
contracts/inventory/inventory-v1.schema.json (unveränderte Version 1.0). Registrierte
server_id und neue inventory_id, Zeitzone, höchstens fünf Minuten Zukunft; keine Gruppen-,
Primärgruppen-, Positions-, ACL- oder administrativen Bewertungsfelder. Beispiele bleiben
maßgeblich. Bestehenden Launcher nicht eigenständig ersetzen. Maximal 10 MiB, siehe Limits.

Phase 13 sendet auf INVENTORY_DOMAIN POST /api/v1/inventories mit geprüftem mTLS, registriertem
Clientzertifikat und server-/zertifikatsgebundenem inventory:submit-Token. Kein Cookie, keine
frei erfundenen Proxy-Identitätsheader, keine Secrets in URL/Prozessargumenten/Logs. Gleicher
Retry behält inventory_id, kanonischen Inhalt und Idempotency-Key. HTTP 202 heißt accepted,
auch bei duplicate=true. Location/status_url authentifiziert abfragen. Keine Phase-14-Verarbeitung
behaupten und nach 409 keine automatische Inhaltsänderung mit alter Identität versuchen.

Phase 14 erhält submission_id als stabile Eingabe, inventory_id/server_id, Originalbytes/JSON,
beide Hashes, Schema, Zeit, Korrelation und unveränderliche Provenienz. Erst dann Payload-
Leserechte für inventory_processor, separate Verarbeitungshistorie/Status und Snapshotreferenz
versioniert freigeben. Originaldaten bleiben append-only. Inventar-ID ist global eindeutig
an kanonischen Inhalt gebunden: mehrere Quellen/Receipts dürfen keinen zweiten fachlichen
Snapshot erzeugen. Aktive registrierte Handler und passende Jobverträge vor Enqueue testen.
Ältere/partial/failed Daten gemäß Phase 0 historisieren und effektive Bereichssichten beachten.

Kein Upload/Processor darf Server registrieren, administrative Metadaten, ACLs, Gruppen oder
Sortierung verändern. Technische Tokens und Browserrollen bleiben getrennt. Quotas/Retention
sowie globale Nutzungszähler gemeinsam planen; keine implizite Reparatur/Löschung. UI folgt
Phase 20–21, sehr hohe Last Phase 23. [Abnahme](phase-11-acceptance.md),
[Architektur](../architecture/inventory-upload.md), [Betrieb](../operations/inventory-upload.md).
