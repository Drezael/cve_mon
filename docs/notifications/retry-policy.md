# Retry und Recovery

Vor der SMTP-I/O wird ein Versuch samt Message-ID, Worker, Fencing-Token und submitting
committed. Die Datenbanktransaktion bleibt während der Netzwerkübertragung geschlossen.
Completion prüft dieselbe Attempt-/Lease-Zuordnung. Stale Worker überschreiben keinen
rekonstruierten Zustand; ihre tatsächlichen Resultate bleiben separat dokumentiert.

Sichere temporäre Fehler erhalten exponentiellen Backoff mit begrenztem Jitter. Höchstens
fünf SMTP-Anwendungsversuche pro Intent; vorhandene Job-Retries sind zusätzlich begrenzt.
4xx vor eindeutiger Ablehnung ist retryfähig, 5xx permanent, TLS-Validierungsfehler geschlossen.
Verbindungsverlust nach DATA ist unklar. Nach Postfix-Annahme übernimmt ausschließlich
dessen bestehende Queue die SMTP-Retries. Unklare Annahmen verlangen Reconciliation.
