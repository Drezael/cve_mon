# Übergabe ab Phase 8

Freigegeben wird die technische PostgreSQL-Job-/Outbox-Grundlage, keine Fachimplementierung.
Phase 8/9 ergänzt Authentifizierung und ausdrücklich autorisierte API-Kontexte. Keine
Job-/Adminberechtigung aus Headerservice-Namen; aktuelle Werkzeuge benötigen private DB-Rollen.
Phase 10 darf autorisierte Verwaltungsereignisse erzeugen, keine automatische Gruppierung.
Phase 11 erstellt beim validierten Upload Jobs/Outbox in derselben Transaktion.

Phasen 14–18 registrieren typisierte Handler und passende DB-Katalogverträge innerhalb
ihres jeweiligen Rollenbereichs. context.complete für atomare DB-Effekte/Outbox/Erfolg,
externe Effekte separat idempotent. Legacy-Daten vor Übernahme ausdrücklich prüfen.
Phase 19 registriert authentifizierte n8n-Ziele, kein Queue Mode; Notification nutzt
weiter Postfix. Phasen 20–22 konsumieren sichere Statusaggregate ohne Jobschreibzugriff.
Phase 23 konkretisiert Retention, Backup/SLA, Kapazität, externe Egressfreigaben und Lasttests.

[Architektur](../architecture/background-jobs.md), [Outbox](../architecture/transactional-outbox.md),
[Betrieb](../operations/event-dispatcher.md), [Testmatrix](../testing/phase-07-test-matrix.md).
