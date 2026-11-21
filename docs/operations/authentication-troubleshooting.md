# Authentifizierung betreiben und prüfen

```bash
CVE_DOCKER_SUDO=1 make auth-check
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/security/verify-auth-secrets.py
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/security/inspect-auth-status.py
CVE_DOCKER_SUDO=1 make auth-integration
.venv/bin/python scripts/security/benchmark-passwords.py
```

Private Dateien unter .runtime/services/<projekt>: api_reader.password, api_security.password,
ca.crt, auth-keys.json und auth-gateway.key. Keyring: active plus keys mit maximal acht
32-Byte-Hexschlüsseln. Verzeichnis 0700, Secrets 0400/0600, keine Symlinks. Entwicklung
legt fehlende zufällige Key-/Gatewaydateien an, überschreibt keine bestehenden. Produktion
benötigt externe Dateien/PKI; keine Secrets in Image oder .env. UID muss zur privaten
Dateifreigabe passen. API allein auf cve_internal/cve_data, kein Hostport/Socket/Capabilities.

Nginx nach api-prepare neu rendern/prüfen: `CVE_DOCKER_SUDO=1 make nginx-check infra-up`.
Ohne Gatewaydatei bleibt Authentifizierung am Ingress geschlossen (503). Gerendertes
privates auth-routes.conf enthält das Gateway-Geheimnis und darf nicht veröffentlicht
oder mit nginx -T in allgemeine Logs kopiert werden. Host/Origin müssen exakt passen.
TLS bleibt am öffentlichen Ingress und an PostgreSQL geprüft; interner Proxy ist HTTP.
Die separate API-Domain liefert für Authpfade 404; HTTP-Mutationen werden mit 426 abgelehnt.

Health live prüft Prozess, ready Reader-/Auth-DB und lebende Wartung. Keine fachlichen
Healthwrites. auth_metrics liefert nur Zähler/aktive Sessions/Rate-Buckets; status_probe
kann keine Passwörter/Faktoren/Sessions lesen. Bei DB-Ausfall readiness/auth 503, live 200;
Logs melden dependency_unavailable ohne Werte. Nicht persistierbare Ausfälle während
DB-Stillstand sind über Readiness/Logs sichtbar, nicht durch erfundene DB-Zähler.

Fehler: 401 generische fehlende/ungültige Identität; 403 Origin/CSRF/Ingress/unerlaubter
Authentifizierungszustand; 429 persistentes Minuten-/Challenge-Limit oder KDF-Backpressure;
503 fehlende Abhängigkeit, Key oder Schema. Nach fehlgeschlagenem Login neues GET csrf.
Keine Ausweitung des TOTP-Fensters als Fehlerbehebung; Systemzeit/NTP kontrollieren.

Cleanup läuft alle 60 Sekunden in begrenzten Batches; zusätzlich `scripts.security.manage cleanup`.
Audit/Login/User-Historie bleibt 90 Tage unveränderlich. Nach geprüftem Archiv/Backup darf
nur der Operator explizit `scripts.security.manage purge-archived --archive-receipt <uuid>`
ausführen (je Tabelle maximal 500 ältere Phase-8-Zeilen); frische und Legacy-Daten bleiben.
Die Archiv-UUID ist ein Operatornachweis, die Software prüft kein externes Archivsystem.
Outbox-Retention bleibt das bestehende separate Betriebsmodell, nicht per Auth-Purge gelöscht.

Gateway-Rotation: neuen privaten Wert kontrolliert bereitstellen, API neu erstellen und
Nginx neu rendern/prüfen/laden. Beide Seiten müssen denselben Wert verwenden; während
eines unvollständigen Wechsels bleiben Authanfragen geschlossen. Keine Ausgabe des Werts.
