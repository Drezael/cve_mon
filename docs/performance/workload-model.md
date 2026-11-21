# Lastmodell Phase 23

Isoliertes cve-db-test-Projekt mit tatsächlichem PostgreSQL, API-Serviceoperationen, Inventarannahme und gefencten Inventory-/Matching-/Findingworkern. Keine normalen Entwicklungs-/Produktivdaten werden als Lastgenerator verwendet. Ein registrierter synthetischer Uploadserver erhält drei aufeinanderfolgende Inventare; zusätzlich werden 100/1000/10000 Server angelegt, insgesamt über 11000. Die Paketstufen betragen 100/1000/10000; Debian/Ubuntu-Versionen und vorhandene Beispielstruktur bleiben erhalten.

Je Stufe 24 tatsächliche ASGI-API-Aufrufe mit vier parallelen Requests, derselben Adminsitzung, Seitenlimit 25 und wechselndem Offset. Gemessen werden alle Latenzproben, nearest-rank p50/p95/p99, Antwortgröße, Fehlerzahl, Upload/Processor/Matching/Findings, Queryplan, Verbindungen und Queuezustände. Dockerstats erfasst CPU/RAM/Block-I/O/PIDs des isolierten PostgreSQL als Stichprobe; Python/Kindprozesse liefern CPU und Spitzen-RSS. Kein Kernel-I/O-Peak oder Produktionslast wird behauptet.

Ergänzende bestehende Tests messen tausend CVE-Datensätze, Enrichment-Backfill, 10000 EPSS-Zeilen, Matching-Backfill, 100 Notificationempfänger, acht parallele Claimer und parallele Uploads. Browserprüfungen verwenden tatsächliches TLS und Seitenansichten, keine behauptete Browserlast aus ASGI-Werten.
