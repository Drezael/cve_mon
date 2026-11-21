# Phase-8-Testmatrix

| Bereich | Reale Nachweise |
|---|---|
| Passwort/Kryptografie | individuelle Argon-Salts, falsche/kaputte/alte Hashes, NFC/Spaces/Längengrenzen, lokaler Weak-Filter, AEAD/AAD/Keys |
| TOTP | sechs offizielle SHA1-RFC-Vektoren, Replay, Fenster, ASCII, paralleler Verbrauch |
| Native DB | Migration 00014 zweimal, bestehende FKs/Constraints, sensible Reads/Writes und Gruppen-/Bootstraprechte negativ |
| Login | gültig/falsch/unbekannt, vier inaktive Zustände, Dummy-KDF-/Fehlervergleich |
| Missbrauch | parallele persistente Kennungslimits, Spraying/IP, globaler Admission- und KDF-Grenzcode |
| Session | host-only sichere Cookies, Fixation, Rotation, idle/absolute/Revoke/Auth-/Credentialversion/Status, logout-all |
| CSRF/Proxy | kein/falscher/fremder Token, falscher Origin/Host/Gateway/Client-IP, doppelte Cookies, Bodygrenze |
| MFA | initiales Admin-Enrollment, Login, alte/fremde Challenges, kein voller Kontext vorher, aktueller Faktor bei Wechsel |
| Recovery | einmalige Ausgabe/Digests, paralleler Einmalverbrauch, MFA-Recovery bleibt eingeschränkt; auch normale MFA-Benutzer |
| Reset/Reauth | intern, zweck-/zeitgebunden, schwaches Passwort/Manipulation/Replays, paralleler Reset/Rotation/Passwortänderung |
| Audit/Outbox | gleicher Commit/Rollback, Ereigniszahl/Metadaten, keine Secrets, aktuelle Historie unveränderlich, kontrollierte Altbereinigung |
| Docker/HTTPS | echtes Nginx + gebaute API + PostgreSQL, vollständiges MFA, falsche CA, HTTP 426/308, API-Domain/Hostmanipulation |
| Ausfall | PostgreSQL stop/start, API-Neustart mit persistierter Session, fehlender Key/kaputter Ciphertext, geschlossene Berechtigungen |
| Betrieb | begrenzte Wartung, Readiness/Logdatenschutz, Bootstrap nur Operator/einmalig, KDF-Messbericht |

Standardlauf: make check. Unit: make auth-test. Gesamtlauf real: CVE_DOCKER_SUDO=1 make
auth-integration; Teilmengen auth-security/auth-mfa-test. Tests verwenden ausschließlich
UUID-Testprojekte, temporäre Benutzer/Secrets und geprüften eigenen Cleanup. Keine produktiven
Konten, externen E-Mails oder fremden Docker-Ressourcen. Regression: db-test, infra-test,
envoy-test, postfix-test, services-integration und automation-integration.
