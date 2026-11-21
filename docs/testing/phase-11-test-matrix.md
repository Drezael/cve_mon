# Phase-11-Testmatrix

| Bereich | Nachweise unter tests/inventory_upload |
|---|---|
| Schema/Parser | unit/test_parser.py: Originalschema, Raw-/kanonische Hashes, Formate, Fuzzing, Unicode, strukturelle Feldverbote |
| Ressourcen | unit/test_boundaries.py: tatsächlich gelesene Bytes, Child-Timeout/Reaping, Multipartcleanup |
| Zertifikate | unit/test_certificates.py und integration/test_technical_security.py: SHA-256, CA/EKU/Laufzeit/CRL, Spoofing, Rotation |
| Persistenz/Idempotenz | integration/test_acceptance.py: Originalbytes, getrennte Quellen, Status und keine Phase-14-Artefakte |
| Dashboard | test_dashboard_security.py: MFA/CSRF/Rollen/ACL, Dateinamen, Zusatzteile, BOLA und Widerruf |
| DB/Quotas | test_limits_integrity.py: native Rollenlogins, Payloadleseverbot, Append-only, Kapazität und Rate |
| Konkurrenz/Ausfall | test_concurrency_recovery.py: echte parallele DB-Transaktionen, Widerruf/Archivierung während Parsing, Audit-/DB-Abbruch, verlorene Antwort, echte API-/PG-Neustarts |
| E2E/Betrieb | reale Nginx-mTLS- und Dashboard-MFA-Uploads, Log-/Mountprüfung, schreibgeschützte Werkzeuge, 5000-Paket-Baseline |
| Regression | sämtliche bisherigen Standard-/Auth-/RBAC-/Server-/DB-/Infrastruktur-/Egress-/Mail-/API-/Job-/Outbox-Suiten |

Make-Ziele inventory-upload-test/security/integration/mtls/concurrency/e2e/check.
Docker mit CVE_DOCKER_SUDO=1. UUID-isolierte Projekte, reale PKI und native Logins. Zwei frische
Clientblätter pro Testfall unter unveränderter eigener Test-CA/CRL, keine produktiven Änderungen.
Fachtests dürfen serverseitige Fixture-Reauth setzen; echte MFA/Reauth bleibt separat in
Authentifizierungsregression geprüft. Keine externen Ansibleänderungen oder Zustellungen.
