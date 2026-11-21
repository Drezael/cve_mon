# Idempotenz und Konkurrenz

Intents besitzen stabile UUIDs sowie Unique Constraints für Event, Empfänger, E-Mail-Kanal,
Regelversion und Ereignisart. Digest-Eltern sind je Empfänger/Regel/UTC-Fenster eindeutig.
Receipts verhindern erneute Entscheidungen für abgeschlossene Ereignisse. Advisory Locks
serialisieren Eventannahme und Rate-Zähler; PostgreSQL schützt Claims mit Zeilensperren.

n8n-Runs haben zufällige Request-UUIDs, fünf Minuten Gültigkeit und einen einmaligen Claim.
Execute prüft Run, Lease, Status und Fencing-Token erneut. Nach persistentem submitting
führen Workerabsturz oder verlorene Bestätigung zu submission_uncertain. Abgelaufene Leases
vor Submit können sicher erneut geplant werden. Nach bestätigter Relayannahme bleibt eine
weitere Submit-Ausführung gesperrt. SMTP selbst bietet keine Exactly-once-Garantie.
