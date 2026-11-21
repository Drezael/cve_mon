# Ereignisannahme

Die Outbox-Trigger erzeugen notifications.consume_event im selben Commit wie das Finding-
Ereignis. Source, Schema 1, Finding-/Server-/CVE-Referenzen, Row-Version und Aggregate-Version
werden geprüft. Veraltete oder nicht unterstützte Ereignisse erhalten ein Receipt; sie
überschreiben keine neuere fachliche Grundlage. Matching-/CVE-Importe allein senden nichts.

Verarbeitet werden created, confirmed_affected, potentially_affected, reopened,
priority_changed, resolved, closed, assigned, deadline_approaching, overdue,
exception_approved, exception_expired und exception_revoked. Ausnahmevorwarnungen sind
eigene notification.exception_approaching-Referenzen; sie verändern kein Finding.

Keyset-Seiten umfassen maximal 100 Benutzer. Folgejobs, Intents und Receipts werden mit
dem vorhandenen Lease-Fence committed. Die letzte Seite schließt das Event-Receipt ab.
Ereigniswiederholungen sind zusätzlich durch Unique Constraints je Event/Empfänger/Kanal/
Regelversion/Art abgesichert. n8n erhält nur zufällige Run-/Request-UUIDs.
