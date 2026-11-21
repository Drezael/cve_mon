# Phase-10-Testmatrix

| Bereich | Nachweis unter tests/server_administration |
|---|---|
| Eingaben/Verträge | unit/test_rules.py, test_contracts.py: Allowlist, Normalisierung, Primärgruppe, starke Preconditions, 4 OpenAPI/4 JSON-Schemas |
| Registrierung/Lebenszyklus | integration/test_lifecycle.py: Idempotenz, UUID, CAS, Metadaten, Gruppen, Archive/Restore |
| Mitgliedschaften/Sortierung | test_ordering.py: drei unabhängige Kontexte, explizite Primärgruppe, parallele gleiche/verschiedene Kontexte, Archivierungsrennen |
| Sicherheit/DB-Rechte | test_security.py: Rollen, native Loginrechte, verschachtelte Inventarfelder, BOLA, Suche/Pagination/Counts, CSRF/Reauth |
| Ausfälle/End-to-End | test_recovery_performance.py: reale API-/PostgreSQL-Neustarts, DB-Ausfall, Backendverbindungsabbruch, Audit-/Membership-/Order-Rollback |
| Last | 2000 Server, 100 Gruppen, 4000 Mitgliedschaften, 500 Grants, 24 parallele ACL-Listen, gleiche Queryanzahl bei 1/100 Ergebnissen, relativer Move |
| Regression | alle bisherigen Standard-, Auth-, RBAC-, DB-, API-, Infrastruktur-, Envoy-, Postfix- und Job-/Outbox-Suiten |

make server-admin-test / server-admin-integration / server-admin-security /
server-admin-concurrency / server-admin-integrity. Docker mit CVE_DOCKER_SUDO=1.
Ausschließlich UUID-isolierte eigene Testprojekte. Wiederverwendete Phase-8-Lab-PKI und echte
Passwort-/MFA-Anmeldungen; Fixture-Owner setzt für Fachtests serverseitige frische Reauth,
die vollständige echte Reauth/TOTP-Suite läuft separat in Regression. Kein Produktionskonto,
keine produktive Serverregistrierung und keine fremden Container-/Volumenänderungen.
