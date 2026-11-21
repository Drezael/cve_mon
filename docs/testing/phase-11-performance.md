# Phase-11-Performance und Ressourcen

Lokale Docker-/PostgreSQL-Testinstanz, 07.11.2026. Gemessen durch
`tests/inventory_upload/integration/test_operations_performance.py`, jeweils ein Upload
mit 5000 Paketen und 584339 Originalbytes, beide Male vollständige Validierung,
Transaktion, Provenienz und Audit/Outbox. Technisch 0.690 Sekunden,
Dashboard 0.719 Sekunden. Einzelmessung auf diesem Entwicklungsrechner,
kein Durchsatzversprechen und keine Hochlastfreigabe. Rohdaten geschützt in
`.runtime/test-reports/phase-11-performance.json`.

Ein Parser gleichzeitig, eigenes Kind mit 256 MiB Adressraum, 12 CPU-Sekunden,
15 Sekunden Walltime, überwachte Beendigung/Reaping. API-Dockerbudget 512 MiB.
Original-JSON maximal 10 MiB, Multipart zusätzlich maximal 1 MiB Rahmen; tatsächliche
Bytes werden auch bei fehlendem/falschem Content-Length gezählt. Keine Dekompression.
Tiefe 32, 750000 Knoten und engere Array-/String-/Schema-Grenzen. 10 Sekunden Bodydeadline,
2 Sekunden begrenzte Parserwarteschlange; Überlast führt zu 429. Native Minutenraten
und Quotas begrenzen Annahme dauerhaft; siehe [Betrieb](../operations/inventory-upload.md).

Nachgewiesen sind konkurrierende Schlüssel, Commitzeit-Widerruf und Recovery, kein
unbegrenzter Parallelbetrieb. Lockreihenfolge G909001/Idempotenz/Quota priorisiert konsistente
Autorisierung. Phase 23 muss größere Bestände, Verbindungspools und höhere Konkurrenz
vermessen. Physischer Speicher umfasst zusätzlich JSONB, Index und WAL; Retention und
Quotazähler sind mit Phase 14 ausdrücklich zu entwickeln.
