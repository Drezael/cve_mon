# ADR-0026 – Lokale serverseitige Authentifizierung

Status: accepted. Datum: 06.11.2026.

cve-api 0.8.0 implementiert lokale Authentifizierung im bestehenden security-Schema.
Additive Revision 00014 verwendet bestehende CSRF-/Origin-/Authversions-/TOTPfelder.
Eigener api_security-Pool zusätzlich zum begrenzten Reader, kein Rollenwechsel.
Browser-Session mit zufälligem opaque Verifikator/Digest, __Host-Cookie und CSRF;
kein JWT, Redis oder IdP. Verbindlicher technischer Vertrag authentication.openapi.yaml.

Argon2id mit mindestens 19456 KiB/t2/p1 und begrenzten Threads. TOTP als SHA1/6/30s,
MFA verpflichtend für Administratoren. AEAD-Keyring außerhalb der DB, benutzergebundene
AAD, atomare Replayprüfung. Recovery führt ausschließlich zu eingeschränktem erneuten
Enrollment; öffentliche Passwortreset-Zustellung bleibt bis zur realen Integration aus.

Security-Änderungen werden mit Benutzerlock, Versionen, Audit und Outbox konsistent
committet. Limits bleiben bei abgebrochenen Verifikationen persistiert. Nginx überschreibt
das private Gateway-/HTTPS-/IP-Merkmal, Auth nur auf dem Dashboard-Origin. Interner
Proxyverkehr bleibt HTTP auf dem privaten Netz; direkter Zugriff kann dieses Gate nicht
durch öffentliche Header ersetzen. AuthBoundary begrenzt Bodies vor der Verarbeitung.

Keine Bootstrap-/Benutzerverwaltungsroute. Operator-only Erstadmin ohne Standardpasswort;
kein automatischer Bootstrap im Deployment. Kontrollierte Session-/Tokenbereinigung,
90-Tage-Auditarchivierung/Purge nur nach ausdrücklich angegebenem Operator-Archivnachweis.
Rollen-/Objektverwaltung, technische Uploadidentitäten und Dashboard-UI bleiben Folgephasen.
