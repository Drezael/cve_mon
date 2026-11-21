# Phase-8-Abnahme

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge, 66 Pflichtprüfungen, 49 Schlusskriterien und 50 AUTH-Invarianten erfüllt.**

781 Tests bestanden: 344 Standardtests (einschließlich 38 Auth-Unit-Tests),
56 Authentifizierungs-Integrationstests, 29 Job-/Outbox-Integrationstests,
10 Service-Integrationstests, 189 PostgreSQL-, 40 Infrastruktur-, 77 Envoy- und
36 Postfix-Tests. Keine ausgelassenen verpflichtenden lokalen Prüfungen.

make check, setup/python-check, Ruff/Format, Mypy (183 Quelldateien), alle Verträge
und beide Compose-Modelle erfolgreich. Secret-Scan mit unveränderter Baseline.
Frische Offline-venv aus Hash-Wheels: API 0.8.0, common/Dispatcher 0.7.0, pip check,
isolierte Imports ohne Netzwerk und mitgelieferte Blocklist/Lizenz geprüft.

[45 Aufgaben](phase-08-status.md), [Dateimanifest](phase-08-files.json),
[Testmatrix](../testing/phase-08-test-matrix.md), [Argon-Messung](../testing/phase-08-performance.md).

## Verpflichtende Prüfungen T08.09.05

| Nr. | Vorgabe | Nachweis |
|---|---|---|
| 1 | Bestehende Security-Tabellen wiederverwendet. | 00014; frische/repetierte Migration, native Privilegientests und 189 DB-Regressionstests |
| 2 | Neue Migrationen versioniert. | 00014; frische/repetierte Migration, native Privilegientests und 189 DB-Regressionstests |
| 3 | Datenbankrechte korrekt. | 00014; frische/repetierte Migration, native Privilegientests und 189 DB-Regressionstests |
| 4 | Keine PostgreSQL-Superuser-Rechte. | 00014; frische/repetierte Migration, native Privilegientests und 189 DB-Regressionstests |
| 5 | Lokale Benutzeranmeldung implementiert. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 6 | Argon2id verwendet. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 7 | Sichere Hashparameter. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 8 | Passwortqualität validiert. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 9 | Keine Klartextpasswörter. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 10 | Keine unnötigen Komplexitätsregeln. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 11 | Sichere Administratorinitialisierung. | operator-only Bootstrap, Advisory-Lock, vorhandener Admin verhindert Wiederholung; kein Standardpasswort |
| 12 | Kein festes Standardpasswort. | operator-only Bootstrap, Advisory-Lock, vorhandener Admin verhindert Wiederholung; kein Standardpasswort |
| 13 | Kontostatus werden berücksichtigt. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 14 | Gesperrte Konten abgelehnt. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 15 | Deaktivierte Konten abgelehnt. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 16 | Archivierte Konten abgelehnt. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 17 | Kein Benutzeraufzählungsproblem. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 18 | Brute-Force-Schutz wirksam. | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets |
| 19 | MFA-Fehlversuche begrenzt. | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets |
| 20 | Session-Token kryptografisch sicher. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 21 | Session-Verifikatoren geschützt gespeichert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 22 | Cookies sicher konfiguriert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 23 | CSRF-Schutz wirksam. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 24 | Session-Fixation verhindert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 25 | Session-Rotation funktioniert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 26 | Inaktivitätsablauf funktioniert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 27 | Absoluter Session-Ablauf funktioniert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 28 | Logout widerruft Session. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 29 | Logout aller Sessions funktioniert. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30 | Passwortänderung widerruft bestehende Sessions. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 31 | Administratormfa verpflichtend. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 32 | TOTP nach RFC 6238. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 33 | TOTP-Secrets verschlüsselt. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 34 | Verschlüsselungsschlüssel geschützt. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 35 | MFA-Enrollment funktioniert. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 36 | Keine Aktivierung ohne TOTP-Bestätigung. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 37 | TOTP-Replay verhindert. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 38 | Paralleler TOTP-Replay verhindert. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 39 | Recovery-Codes sicher erzeugt. | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| 40 | Recovery-Codes geschützt gespeichert. | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| 41 | Recovery-Codes nur einmal verwendbar. | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| 42 | Recovery ermöglicht keine unkontrollierte MFA-Umgehung. | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| 43 | Reauthentifizierung funktioniert. | frische sessiongebundene einmalige Reauth, parallele Rotation und Faktorwechsel negativ |
| 44 | Passwortreset-Tokens sicher. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 45 | Passwortreset-Tokens nur einmal verwendbar. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 46 | Nicht verfügbare Passwortreset-Zustellung bleibt deaktiviert. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 47 | Keine Secrets in Logs. | test_audit_outbox_atomicity_and_no_cleartext_verifiers; Containerlogs/Secrets und kontrollierte Retention |
| 48 | Audit-Ereignisse nachvollziehbar. | test_audit_outbox_atomicity_and_no_cleartext_verifiers; Containerlogs/Secrets und kontrollierte Retention |
| 49 | Transactional Outbox integriert. | test_audit_outbox_atomicity_and_no_cleartext_verifiers; Containerlogs/Secrets und kontrollierte Retention |
| 50 | Keine unbeabsichtigten öffentlichen API-Endpunkte. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 51 | Nginx-Integration sicher. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 52 | Manipulierte Proxy-Header werden nicht vertraut. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 53 | Keine unnötigen Containerprivilegien. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 54 | Kein Docker-Socket. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 55 | Keine zusätzlichen Datenbanksysteme. | Compose/Architektur: PostgreSQL, kein weiterer Datenbank-/Authdienst |
| 56 | Unit-Tests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 57 | Integrationstests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 58 | MFA-Tests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 59 | Sicherheitstests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 60 | Konkurrenztests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 61 | Fehler- und Wiederherstellungstests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 62 | Dokumentation vollständig. | Architektur, Verträge, Threat Model, Security-/Betriebsdokumente und Testmatrix |
| 63 | Übergabe an Phase 9 vorbereitet. | phase-08-handover.md; zentrale authenticated_user-Dependency und aktueller Reauth-Kontext |
| 64 | Keine Benutzerverwaltungsfunktionen vorzeitig implementiert. | nur elf Authrouten, keine allgemeinen Benutzer-/Rollen-/Gruppen-/Uploadfunktionen; Originalvorgaben unverändert |
| 65 | Keine technischen Inventar-Upload-Tokens vorzeitig implementiert. | nur elf Authrouten, keine allgemeinen Benutzer-/Rollen-/Gruppen-/Uploadfunktionen; Originalvorgaben unverändert |
| 66 | Keine unzulässigen Architekturänderungen. | nur elf Authrouten, keine allgemeinen Benutzer-/Rollen-/Gruppen-/Uploadfunktionen; Originalvorgaben unverändert |

## Schlusskriterien aus Abschnitt 30

| Bereich | Vorgabe | Nachweis |
|---|---|---|
| 30.1 | Argon2id. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.1 | Sichere Hashparameter. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.1 | Passwortqualitätsprüfung. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.1 | Keine Klartextspeicherung. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.1 | Sichere Passwortverifikation. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.1 | Sichere Passwortänderung. | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline |
| 30.2 | Login. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.2 | Kontostatusprüfung. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.2 | Schutz vor Benutzeraufzählung. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.2 | Brute-Force-Schutz. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.2 | Rate-Limiting. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.2 | Sicherheitsevents. | test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| 30.3 | Kryptografisch sichere Tokens. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Geschützte Speicherung. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Sichere Cookies. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Session-Rotation. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Inaktivitätsablauf. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Absoluter Ablauf. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Logout. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | Widerruf aller Sessions. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.3 | CSRF-Schutz. | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| 30.4 | TOTP. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Administrator-MFA-Pflicht. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Sicheres Enrollment. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Verschlüsselte Secrets. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Replay-Schutz. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Recovery-Codes. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Sichere Faktoränderung. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.4 | Keine MFA-Umgehung. | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| 30.5 | Sichere Reset-Tokens. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 30.5 | Einmalige Verwendung. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 30.5 | Session-Invalidierung. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 30.5 | Keine unerlaubte MFA-Deaktivierung. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 30.5 | Keine ungesichert freigeschaltete E-Mail-Wiederherstellung. | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| 30.6 | FastAPI-Integration. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Nginx-HTTPS-Zugang. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Korrekte Datenbankrechte. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Geschützte Secret-Dateien. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Keine unnötigen öffentlichen Ports. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Kein Docker-Socket. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.6 | Keine unnötigen Containerprivilegien. | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| 30.7 | Ruff erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Mypy erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Unit-Tests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Integrationstests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Sicherheitstests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Konkurrenztests erfolgreich. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Dokumentation vollständig. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |
| 30.7 | Übergabe an Phase 9 vorbereitet. | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |

## Sicherheitsinvarianten

| ID | Regel | Nachweis |
|---|---|---|
| AUTH-01 | Lokale Authentifizierung über PostgreSQL | nur bestehende PostgreSQL-Security-Strukturen, kein automatischer Admin; Bootstrapwerkzeug explizit/privat |
| AUTH-02 | Keine zusätzliche Authentifizierungsdatenbank | nur bestehende PostgreSQL-Security-Strukturen, kein automatischer Admin; Bootstrapwerkzeug explizit/privat |
| AUTH-03 | Kein Redis | nur bestehende PostgreSQL-Security-Strukturen, kein automatischer Admin; Bootstrapwerkzeug explizit/privat |
| AUTH-04 | Kein öffentliches Standardadministratorkonto | nur bestehende PostgreSQL-Security-Strukturen, kein automatischer Admin; Bootstrapwerkzeug explizit/privat |
| AUTH-05 | Keine fest eingebauten Standardpasswörter | nur bestehende PostgreSQL-Security-Strukturen, kein automatischer Admin; Bootstrapwerkzeug explizit/privat |
| AUTH-06 | Passwörter nur als Argon2id-Hashes | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline; test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| AUTH-07 | Passwortqualität wird serverseitig geprüft | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline; test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| AUTH-08 | Passwörter werden nicht in Logs geschrieben | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline; test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| AUTH-09 | Unbekannte Benutzer werden nicht offengelegt | 38 Unit-Tests: Argon2id/Salts/Rehash/Policy/NFC; KDF-Baseline; test_flows/test_security: gültig/falsch/unbekannt, vier inaktive Zustände, generische Fehler und Dummy-KDF |
| AUTH-10 | Gesperrte Benutzer können sich nicht anmelden | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets; aktive Status-/Kontoprüfungen |
| AUTH-11 | Deaktivierte Benutzer können sich nicht anmelden | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets; aktive Status-/Kontoprüfungen |
| AUTH-12 | Archivierte Benutzer können sich nicht anmelden | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets; aktive Status-/Kontoprüfungen |
| AUTH-13 | Brute-Force-Versuche werden begrenzt | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets; aktive Status-/Kontoprüfungen |
| AUTH-14 | MFA-Versuche werden begrenzt | test_persistent_parallel_brute_force_and_spraying_limits; persistente IP/Kennung/Challenge-Buckets; aktive Status-/Kontoprüfungen |
| AUTH-15 | Administratoren benötigen MFA | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-16 | Keine vollständige Administratorsession vor MFA | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-17 | TOTP verwendet RFC 6238 | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-18 | Ein erfolgreich verwendeter TOTP-Code darf nicht erneut verwendet werden | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-19 | TOTP-Secrets werden verschlüsselt | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-20 | TOTP-Schlüssel werden außerhalb PostgreSQL verwaltet | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-21 | MFA wird erst nach Bestätigung aktiviert | RFC-6238-Vektoren, AEAD/AAD/Keys, vollständiger HTTPS-MFA-Ablauf und paralleler TOTP-Replay |
| AUTH-22 | Recovery-Codes sind einmalig verwendbar | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| AUTH-23 | Recovery-Codes werden nicht im Klartext gespeichert | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| AUTH-24 | Recovery-Codes umgehen nicht unkontrolliert die Administrator-MFA | einmalige Recovery-Digests, paralleler Verbrauch, restricted Recovery auch bei normalen MFA-Benutzern |
| AUTH-25 | Browser-Sessions werden serverseitig verwaltet | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-26 | Session-Token sind kryptografisch zufällig | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-27 | Session-Verifikatoren werden geschützt gespeichert | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-28 | Cookies verwenden Secure | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-29 | Cookies verwenden HttpOnly | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-30 | Cookies verwenden SameSite | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-31 | Cookies sind an den vorgesehenen Host gebunden | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-32 | Session-Fixation wird verhindert | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-33 | Sessions besitzen Inaktivitätsgrenzen | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-34 | Sessions besitzen absolute Ablaufzeiten | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-35 | Logout widerruft die Session | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-36 | Passwortänderungen widerrufen alte Sessions | Session-/CSRF-/Rotation-/Ablauf-/Logout-/Versions-/Passwortänderungs- und Reaktivierungstests |
| AUTH-37 | CSRF-Schutz ist verpflichtend | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung; strikter Origin/CSRF |
| AUTH-38 | Unvertrauenswürdige Proxy-Header begründen keine Identität | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung; strikter Origin/CSRF |
| AUTH-39 | Sicherheitskritische Änderungen benötigen Reauthentifizierung | frische sessiongebundene einmalige Reauth, parallele Rotation und Faktorwechsel negativ |
| AUTH-40 | Passwortreset-Tokens sind einmalig und zeitlich begrenzt | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| AUTH-41 | Passwortreset deaktiviert nicht automatisch MFA | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| AUTH-42 | Keine öffentlich aktivierte Resetfunktion ohne sichere Zustellung | ResetTokens: Ablauf/Zweck/Manipulation/Policy/Parallelität; kein öffentlicher Reset-/Zustellendpunkt |
| AUTH-43 | Sicherheitsereignisse enthalten keine Secrets | test_audit_outbox_atomicity_and_no_cleartext_verifiers; Containerlogs/Secrets und kontrollierte Retention |
| AUTH-44 | Audit und Outbox werden wiederverwendet | test_audit_outbox_atomicity_and_no_cleartext_verifiers; Containerlogs/Secrets und kontrollierte Retention |
| AUTH-45 | Keine allgemeinen Benutzerverwaltungs-APIs in Phase 8 | nur elf Authrouten, keine allgemeinen Benutzer-/Rollen-/Gruppen-/Uploadfunktionen; Originalvorgaben unverändert |
| AUTH-46 | Keine technischen Inventar-Upload-Tokens in Phase 8 | nur elf Authrouten, keine allgemeinen Benutzer-/Rollen-/Gruppen-/Uploadfunktionen; Originalvorgaben unverändert |
| AUTH-47 | Kein öffentlicher Datenbank- oder API-Containerport | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| AUTH-48 | Kein Docker-Socket | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| AUTH-49 | Keine unnötigen Containerprivilegien | test_deployment: echte CA/HTTPS/Host-/Proxygrenze, direkter Backendzugriff, Containerhärtung |
| AUTH-50 | Sicherheitsmechanismen werden mit Negativtests überprüft | 781 erfolgreiche Tests: 344 Standard, 56 Auth, 29 Automation, 10 Services, 189 DB, 40 Infra, 77 Envoy, 36 Postfix |

## Tatsächlicher lokaler Betrieb

00014_authentication ist angewendet. API 0.8.0, Nginx, PostgreSQL, Envoy, Postfix und
Event Dispatcher sind gesund. Echtes Dashboard-HTTPS liefert 200 für den CSRF-Bootstrap,
Cookieattribute und getrennte API-Domain 404 geprüft. API hat keinen Hostport, läuft
Nicht-Root/readonly/CapDrop ALL und nur auf cve_internal/cve_data. Eigene private Reader-/
Security-Credentials, getrennte versionierte Keyring-/Gatewaydateien; kein SET ROLE in Runtime.

Keine produktiven Benutzer, Credentials, MFA-Methoden oder Sessions automatisch erzeugt.
Der normale Stack besitzt keinen Defaultadministrator. Testadmins/Secrets nur in eigenen
UUID-Projekten; vier fremde Nextcloud-Container behalten ihre IDs. Die technische anonyme
CSRF-Betriebsprobe ist kurzlebig und besitzt keine Benutzeridentität oder Fachrechte.

## Rückwirkungen auf frühere Phasen

Die vorhandenen Security-CSRF-/Origin-/Authversions-/Idle-/TOTPfelder werden wiederverwendet.
Eine additive Revision 00014, alte 13 Revisionen und alle dev_docs-/Phase-0-Originalverträge
unverändert. Neuer konkreter Authvertrag 0.8.0 unter /api/v1/auth; Phase-0-Planungsrouten
unter /api/v1/dashboard/auth bleiben geschlossen, keine irreführenden inkompatiblen Aliasse.
API wächst auf 0.8.0, common und Dispatcher bleiben 0.7.0. Neue gesperrte externe Kryptobibliotheken,
gezielte Compose-/Nginx-/Bootstrap-/Validator-/CI-Ergänzungen und erwarteter Migrationsstand 14.
Bestehende Ingress-/DB-/Egress-/Mail-/API-/Job-/Outbox-Suiten vollständig erneut geprüft.

## Grenzen und Folgearbeit

Backend-API ohne Dashboard-UI und ohne allgemeine Benutzer-/Rollenverwaltung. Öffentliche
Passwortreset-Zustellung bleibt deaktiviert; interne Primitive versprechen keine E-Mail.
Bootstrap wird ausschließlich bewusst durch den Operator mit eigener Kennung und privatem
Passwort ausgeführt. TOTP ist kein Phishingschutz; gültige gestohlene Cookies bleiben bis
Widerruf/Timeout Bearer-Credentials. Privater Nginx→API-Verkehr ist intern HTTP; öffentliche
HTTPS- und PostgreSQL-TLS-Prüfungen bleiben aktiv. Vollständige Produktionslast-/XSS-/Timing-
und weitergehende Betriebsfreigaben sind keine lokale Phasenabnahme.

Audit-Purge älterer Phase-8-Daten nur nach explizitem Operator-Archivnachweis, maximal 500
je Tabelle; aktueller/Legacy-Auditbestand bleibt unveränderlich. Die Software prüft die
externe Archiv-UUID nicht selbst gegen einen Archivdienst. Authdaten-Cleanup ist begrenzt,
Outbox-Retention bleibt separat. Schlüsselbackup und versionierte Rotation dokumentiert.

Keine offenen verpflichtenden lokalen Phase-8-Arbeiten. Phase 9 wurde nicht begonnen.
Gehostete CI mangels Veröffentlichung nicht ausgeführt, kein Commit/Push. Lokale Logs,
Unit-XML und Messdaten liegen ignoriert unter .runtime/test-reports/phase-08-*.

[Übergabe](phase-08-handover.md), [Betrieb](../operations/authentication-troubleshooting.md),
[Administrator initialisieren](../operations/initial-administrator.md).
