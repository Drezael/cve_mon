# Benachrichtigungsverträge 1

Pydantic-Modelle sind die ausführbare Quelle für Regeln, Präferenzen und Vorlagen.
workflow-command beschreibt ausschließlich zufällige Run-/Request-Referenzen. Ereignis-,
Intent- und Zustellverträge trennen Fachentscheidung, SMTP-Annahme und tatsächliche Zustellung.
Browser-API: ../api/notification-management.openapi.yaml. Interne Endpunkte sind niemals
öffentliche Mailversandschnittstellen; Adressen und Netzwerkziele sind keine Auftragsparameter.
