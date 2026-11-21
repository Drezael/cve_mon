# Interne SMTP-Clientauthentifizierung

Client verbindet zu cve-mail-relay:2525, prüft CA/Hostname bei STARTTLS und präsentiert
eigenes clientAuth-Zertifikat. Relay erfordert CA-Kette und exakten SHA256-Zertifikatpin.
Freigabe in policy.json: Inhaber/name, purpose, enabled, fingerprint, senders.
Private Clientschlüssel verbleiben ausschließlich beim Client. Entzug durch Entfernung
oder Deaktivierung des Pins und `make mail-up`; bestehende Prozesse werden ersetzt.
Rotation und dateibasiertes Betreiberverfahren: [Deployment](../deployment/postfix.md).
