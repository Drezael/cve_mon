# Übergabe an Phase 22

Phase 21 stellt die vorgesehenen administrativen Fachoperationen im vorhandenen Dashboard
bereit. Maßgeblich bleiben die APIs aus Phase 8–19 und deren serverseitige Zustandsmaschinen.
Es gibt keine endgültige Serverlöschung, neue Passwort-Reset-Ausstellung, gespeicherten
Filter-/Exportverträge oder freien SMTP-Testversand. Dafür existieren keine freigegebenen
Backendverträge; keine Attrappen oder Ersatz-APIs ergänzen.

Weitere Phasen übernehmen Betrieb/Qualität nach ihrem eigenen Plan. Einstiegspunkte:
services/dashboard/src/admin, src/api.ts, cve_api.dashboard.administration, Migration 00029.
Bauen: make administration-check; native/API/Browser: CVE_DOCKER_SUDO=1 make administration-e2e.
Aktivierung wie Phase 20 über bestehenden API-/Nginx-Stack und make dashboard-up.
Rollback: passendes vorheriges API-Image und vorherige statische HTML-/Assetgeneration
aktivieren; additive Lesesichten können bestehen bleiben. Kein destruktives Downgrade.
