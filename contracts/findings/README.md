# Finding-Verträge v1

finding.schema.json beschreibt den geschützten Finding-Lesevertrag; finding-event.schema.json
die kompakten Outbox-Referenzen; finding-history.schema.json die append-only-Auditkette;
finding-exception.schema.json befristete Requests; finding-priority.schema.json die versionierte
Operatorpolicy. Die Browser-API liegt unter /api/v1/findings auf der vorhandenen Dashboard-Origin.
Notizen sind Plaintext. Technische Matching-Felder und Akteure sind nicht mass-assignable.
