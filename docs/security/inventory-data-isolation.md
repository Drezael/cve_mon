# Datenhoheit und native Privilegien

Uploads schreiben ausschließlich neue Annahmen, Idempotenzmetadata und vorgesehene Audit/
Outbox. api_ingest/api_security erhalten INSERT und begrenzte Metadata-SELECT-Spalten auf
submissions; SELECT payload_raw/payload_json bleibt verboten. Payloadinspektion ist eine
explizite Betreiberbefugnis, kein Status-API-Recht. inventory_processor erhält derzeit keine
neuen Payloadrechte; diese werden erst mit Phase 14 gezielt aktiviert.

Weder technische Upload-/Processor-/Matching-/Dispatcherrollen noch api_security erhalten
administrative Gruppen-, Primärgruppen-, Kritikalitäts- oder Positionswrites. Native PKs/FKs,
SHA-256-/JSONB-Bytegleichheit, unveränderliche Identitätsregistry, Quotas, aktive Server und
kohärente Token-/Sessionprovenienz ergänzen aktuelle Autorisierung im Backend. Keine
automatische Serverregistrierung, kein Inventarsnapshot, kein Fachjob in Phase 11.

Administrative Schlüssel werden strukturell und normalisiert abgewiesen, auch verschachtelt
und mit alternativen Trennzeichen. Wörter in erlaubten Paketnamen/Versionsstrings werden
nicht als Anweisungen interpretiert. Schema zusätzliche Felder überall verboten. Ungültige
UTF-8-/JSON-Werte, doppelte Schlüssel, nicht endliche Zahlen und für JSONB nicht darstellbare
NUL-Zeichen führen zu kontrolliertem Fehler. Keine partielle Entfernung von Daten.

Payload, Quotaänderung, Audit und Outbox teilen eine Transaktion. Erfolgreiche Duplikate
werden nicht erneut auditiert. PostgreSQL-Logs bleiben terse, ohne SQL-/Bindparameter;
strukturierte API-Logs enthalten keine Payloads, Tokens oder Zertifikatskörper.
