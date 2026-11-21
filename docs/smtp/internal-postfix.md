# Interner SMTP-Adapter

Adapter verbindet ausschließlich cve-mail-relay:2525. smtplib wird mit festem Host initialisiert,
damit STARTTLS die richtige Serveridentität validiert. TLS mindestens 1.2, vertrauensgebundene
CA, eigenes Notification-Clientzertifikat, feste Timeouts, kein Klartext-Fallback. Envelopes
und Header sind getrennt validiert. Stabile Message-ID: <Intent-UUID@cve-monitoring.invalid>.

Postfix prüft Clientzertifikat/Fingerprint sowie explizite Absender- und Empfängerfreigaben
aus Phase 5. Phase 19 öffnet diese nicht automatisch. Fehler beim QUIT ändern eine bereits
bestätigte DATA-Annahme nicht nachträglich in einen Retry. Die Anwendung manipuliert keine
Postfix-Queue und mountet keinen Docker-Socket.
