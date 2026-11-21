# Bedrohungsmodell Authentifizierung

| Angriff | Technische Grenze | Praktischer Test |
|---|---|---|
| Passwort-/DB-Diebstahl | Argon2id, Salt, nur Token-/Code-Verifikatoren, AEAD-Key außerhalb DB | Primitive, persistierte Verifikatoren/Ciphertext |
| Schwache Passwörter | NFC, Länge, lokale Digest-Blocklist, keine externen Passwortabfragen | Policy-Grenzen, Unicode/Spaces/Blocklist |
| Credential Stuffing/Spraying | persistierte globale/IP-/Kennungs-/Challenge-Buckets, begrenzte KDFs | parallele Fehlversuche, IP-Spraying |
| Benutzeraufzählung | generische 401, Dummy-KDF auch bei unbekanntem Konto | identische Fehler ohne Request-ID; grober Timingvergleich |
| Administrativer Kontostatus | jede Sessionprüfung liest aktiven Status/Authversion | locked/disabled/archived/pending und laufende Deaktivierung |
| Sessiondiebstahl/Fixation | opaque Zufallswerte, Hash, Rotation, unmittelbarer Widerruf | fremde Tokens, alte Cookies nach Logout/Reauth/Passwortänderung |
| Cookie-/Subdomainfehler | Host-only __Host-, Secure/HttpOnly/Strict, festes Dashboard | reale Set-Cookie-Header, API-Domain 404, Host/SNI 421 |
| CSRF/Login-CSRF | exakter Origin plus sessiongebundener Digestvergleich | fehlende/falsche/fremde Tokens, manipulierter Origin |
| Rollen-/Proxyheader | keine Headeridentität, privates überschriebenes Ingress-Gate | direct backend, gefälschtes Gateway/X-Role/X-Forwarded-For |
| MFA-Bypass | vollständige Identität erst nach verpflichtendem Faktor | protected dependency vor/nach MFA, Reauth ohne Code |
| TOTP-Replay | monotone persistierte Zeitstufe unter Zeilenlock | RFC-Vektoren, alter/entfernter Schritt, acht parallele Requests |
| Enrollment-Hijacking | Challenge-ID-Bindung, Ablauf, keine frühe Aktivierung | falscher Code, fremder eingeschränkter Kontext |
| Recovery-Diebstahl | zusätzlich Passwort, Einmalverbrauch, eingeschränkte Wiederherstellung | paralleler Codeverbrauch, kein voller Kontext ohne neues TOTP |
| Faktorverlust/Wechsel | historische MFA verhindert Passwort-only-Neueinrichtung | unabhängiger Login während Recovery, frische MFA-Reauth |
| Resetmissbrauch | keine öffentliche Route, Digest/Zweck/TTL, atomarer Verbrauch, MFA bleibt | Ablauf/Manipulation/Zweck/Replay/Parallelität, keine E-Mail |
| Secret-Key-Verlust | versionierte private Dateien; Start/Verifikation geschlossen | fehlender Key, manipuliertes Ciphertext, falsche AAD/Schlüssel |
| Ressourcenmissbrauch | 8-KiB/5-s-Bodies, KDF-Semaphore/Timeout, Pools/Containerlimits | Bodygrenze, parallele KDFs, Docker-Härtung/Messung |
| DB-/Prozessausfall | keine flüchtige Session-Fallbackberechtigung | PostgreSQL stop/start, API-Neustart mit persistierter Session |
| Audit-/Outboxfehler | zusammen mit Security-Effekt committen oder zurückrollen | Rollback-Nachweis und negative native Rechte |
| Auditdatenwachstum | Admission-Limits, Cleanup-Batches, 90-Tage-Archiv/Purge nur Operator | alte vs. aktuelle/Legacy-Auditzeilen, verbotene Runtime-Purge |
| Secret-Leaks | SecretStr, generische Problemantworten/JSON-Logs, no-store | Marker in Logs/Audit/Outbox, private Dateiarten/Modi |

Grenzen: TOTP ist phishbar. Same-Origin-XSS kann trotz HttpOnly Aktionen auslösen.
Ein tatsächlich gestohlener gültiger Browsercookie bleibt bis Widerruf/Timeout ein
Bearer-Credential; TLS und kurze Lebensdauer reduzieren das Risiko. Hostroot und API-
Prozess mit Schlüsseln sind vertrauenswürdig. Interner Proxyverkehr ist in dieser
Architektur HTTP im privaten Netz. Ein globaler Loginengpass kann Verfügbarkeit unter
Angriff reduzieren; der feste Minutenzeitraum verändert niemals administratives locked.
Vollständige Produktionslast-/Timing-/XSS-/WebAuthn-Untersuchungen bleiben Folgearbeiten,
keine Behauptung konstanter Netzwerkantwortzeit oder Phishingresistenz.
