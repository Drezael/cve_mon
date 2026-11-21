# Phase-5-Übergabe

Phase 6 erhält den SMTP-Vertrag aus [Deployment](../deployment/postfix.md).
Phase 7 verwaltet fachliche Jobs in PostgreSQL; SMTP-Retry verbleibt ausschließlich
bei Postfix. Phase 18 erzeugt Ereignisse, versendet nicht selbst. Phase 19 registriert
`cve-notification` mit eigenem Clientzertifikat/-schlüssel und expliziten Sendern;
n8n orchestriert, erhält keine Providercredentials. Phasen 21/22 zeigen bereinigte
Zustände und getrennte lokale/Provider-Verfügbarkeit. Phase 23 integriert verschlüsselte
Backups, Hostquotas, PKI-Erneuerung und Produktions-Startautomation.

Normalzustand ohne Betreiberfreigaben: geschlossene Policy. Vor produktivem Versand
Provider-FQDN/Port/CA und AUTH-Dateien, Empfänger/Sender, Clientpins und externe PKI
bereitstellen. Noch nicht implementierte Fachservices bleiben spätere Phasen; diese
Phase startet weder Notification noch n8n oder eine Statuspage.

[Queue/Recovery](../operations/postfix-backup-restore.md),
[Sicherheitsentscheidung](../architecture/decisions/ADR-0023-postfix-phase05.md).
