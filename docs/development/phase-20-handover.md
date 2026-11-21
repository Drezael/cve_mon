# Übergabe an Phase 21

Phase 20 liefert den lesenden Dashboardrahmen. Phase 21 darf die bereits serverseitig abgesicherten Verwaltungsabläufe in eigene Dialoge überführen: Benutzer/Rollen/ACL, Server/Gruppen/Primärgruppen/Sortierung, Inventar- und Credentialverwaltung, Finding-Triage und Notification-Konfiguration. Reauthentifizierung, CSRF, ETags/Versionen und Konfliktbehandlung sind dabei aus den vorhandenen APIs zu übernehmen. Keine Schreibbuttons als Attrappen ergänzen. Bestehende Scope-, Session- und Browsertests erweitern.

Buildwerkzeug services/dashboard, Backend cve_api.dashboard, additive Migration 00028, Deployment scripts/dashboard. Kein normaler Benutzer, Testinventar oder Versand ist für die Entwicklung erforderlich; Fixtures gehören in isolierte Docker-Projekte.
