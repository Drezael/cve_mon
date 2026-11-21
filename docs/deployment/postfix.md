# Postfix – Betrieb ab Phase 5

Postfix 3.11.7 (Alpine, Projektimage `cve-postfix:3.11.7-phase23`) ist der einzige SMTP-Relay.
Der Python-/Alpine-Basisdigest und 16 signierte APKs mit URL und SHA256 stehen in
`infrastructure/mail/Dockerfile` und `packages.lock.json`. Der Build lädt diese
Artefakte vorab, verifiziert sie und installiert ohne Netzwerk. Keine zusätzliche
Python-Abhängigkeit, keine alternative Mailqueue. Python übernimmt ausschließlich
Konfiguration, Startbarriere, Healthcheck und Log-Redaktion.

```bash
CVE_DOCKER_SUDO=1 make mail-build mail-secrets mail-up mail-check
CVE_DOCKER_SUDO=1 make mail-test
CVE_DOCKER_SUDO=1 make mail-queue
CVE_DOCKER_SUDO=1 make mail-down
```

Voraussetzungen wie Phase 4: Linux, Docker Compose, nft, iproute2, nsenter und
OpenSSL. sudo wird nur bei explizit eingerichtetem passwortlosem Zugang verwendet.
Kein Eingriff in Host-Firewall oder fremde Container. Keine veröffentlichten Ports.

## Konfiguration und Freigabe

`mail-secrets` erstellt ausschließlich in development eine kurzlebige lokale PKI
und zufällige unbrauchbare Provider-Credentials; vorhandene Dateien bleiben erhalten.
Standard: `enabled=false`, keine Clients, keine Empfänger, `smtp.example.invalid`.
Es gibt ohne Betreiberkonfiguration keinen externen Mailversand.

Projektpfad: `.runtime/mail/<COMPOSE_PROJECT_NAME>/`.
`state/policy.json` enthält genau `enabled`, `smarthost`, `port`, `clients`,
`recipients`, `settings`. Clients benötigen `name`, `purpose`, `enabled`,
`fingerprint` (SHA256 mit Doppelpunkten) und `senders` (explizite Mailadressen).
Keine Wildcards; Empfänger sind ebenfalls explizite Mailadressen.
`settings` erlaubt nur die begrenzten Größen-/Queue-/Zeitparameter aus
`scripts/infrastructure/mail.py`; Zeitwerte sind Sekunden. Die unveränderten
Produktionsdefaults betragen fünf Tage Queue-Lebensdauer, einen Tag Bounce-
Lebensdauer, 60–3600 Sekunden Backoff, 1 MiB Nachrichtengröße, 20 Empfänger und
10 MiB freie Queue-Reserve. CPU, RAM, Prozesse, Verbindungen und Logrotation sind begrenzt.
Die Volume-Kapazität/Host-Disk-Quota legt der Betreiber fest; `queue_minfree` schützt
vor weiteren Annahmen unterhalb der Reserve, ersetzt aber keine Host-Kapazitätsplanung.

Unter `state/` liegen `client-ca.crt`, `upstream-ca.crt`, `server.crt`.
Unter `secrets/` liegen ausschließlich `server.key`, `smtp_username`, `smtp_password`
als private reguläre Dateien (0400/0600, keine Symlinks); Verzeichnis 0700.
Keine Werte in Umgebungsvariablen, Argumenten, Compose oder Envoy.
Produktiv: externe PKI/Providerdateien bereitstellen, keine development-only-Markierung.
Die Test-CA und Test-Credentials sind keine Produktionsvorgaben.

`mail-up` validiert, erstellt Postfix neu mit erhaltener Queue, bindet den tatsächlichen
Container an Envoy, installiert Filter nur in diesen eigenen Netznamespaces und
öffnet anschließend die Bootbarriere. SMTP lauscht nur an der internen Adresse.
Nach einem rohen Docker-/Host-Neustart bleibt die neue Netznamespace absichtlich
bis `make mail-up` gesperrt. Diesen Operator-Aufruf in die Host-Startautomation aufnehmen.
Kein ungeschütztes automatisches Wiederanlaufen vor Firewallinstallation.

## Native SMTP-Identität

Interner Vertrag: `cve-mail-relay:2525`, EHLO, STARTTLS mit CA- und Hostnamenprüfung,
autorisiertes Clientzertifikat mit clientAuth-EKU. Der private Clientschlüssel bleibt
beim jeweiligen Client und wird niemals an Postfix oder Envoy gemountet.
CA-Vertrauen allein reicht nicht: exakte SHA256-Zertifikatpins sind zusätzlich erforderlich.
Jeder Pin hat eigene Envelope-Sender; Empfänger sind separat beschränkt. Nullsender,
fremde From-Header und zusätzliche Sender/Reply-To/Resent-Identitäten werden abgelehnt.
From muss eine freigegebene einfache Adresse sein; Anzeigenamen sind bewusst nicht erlaubt.

Extern immer `[cve-egress-proxy]:1587`, fester erlaubter Provider und Port in Envoy.
Postfix verlangt STARTTLS und `secure match=<echter-smarthost> servername=<echter-smarthost>`.
Envoy transportiert TCP Server-First unverändert; Postfix prüft die echte Providerkette
und den echten Namen. Ein gültiges Zertifikat nur für `cve-egress-proxy` genügt nicht.
AUTH PLAIN/LOGIN ist nur nach verifiziertem TLS erlaubt, kein Klartext-Fallback.
`smtp_bind_address=0.0.0.0` lässt die Route die Egress-Quelladresse auswählen;
der Listener bleibt unabhängig davon strikt an die interne Adresse gebunden.

Rotation: neue Datei privat atomar ersetzen, `mail-up`; Provider-Credentials abgestimmt
beim Provider umstellen. Zertifikatsrotation: neuen Pin überlappend freigeben,
Client umstellen, alten Pin entfernen, `mail-up`. Erneuerung von Server-/CA-Zertifikaten
vor Ablauf planen. Ein entferntes Zertifikat erhält auch mit gültiger CA kein Relayrecht.

## Betrieb und Übergabe

[Queue/Recovery](../operations/postfix-backup-restore.md),
[Sicherheit](../security/postfix-security.md), [Tests](../testing/phase-05-test-matrix.md).
Healthcheck kontrolliert lokalen Master, qmgr, native Sockets, Queue-Schreibrechte
und freien Platz; er versendet keine Nachricht und benötigt keinen Provider.
Getrennte Statuspage-Probe: SMTP-Banner/EHLO/STARTTLS, CA und Hostname prüfen,
anschließend QUIT ohne MAIL/RCPT/DATA. Keine SMTP-Credentials in Statusantworten.
JSON-Logs enthalten nur Zeit, Komponente, Queue-ID, native DSN, Zustellstatus und
feste Fehlerkategorien; keine Rohantworten, Envelope-Adressen, Header oder Inhalte.
Queue-Inspektion nur administrativ: `mail-queue` enthält personenbezogene Adressen.
Fehlerdiagnose: Dienststatus, Queue-ID/DSN, TLS-Namen/CA, Pin, Dateirechte,
Namespace-Guard und Kapazität prüfen. Niemals Debug-Protokolle mit AUTH veröffentlichen.

Die spezifizierten `postfix-check`, `postfix-test`, `postfix-security`,
`postfix-queue-test`, `postfix-relay-test` sind Make-Einstiegspunkte. Der vollständige
CI-Workflow führt auch die früheren Phasen erneut aus; sein Zeitlimit beträgt 30 Minuten.
Die lokale Gesamtabnahme ist ausgeführt, ein entfernter CI-Lauf wird damit nicht behauptet.

Phase-23-Härtung und geprüfte Updatewege: [Runtime-Behebung](../security/phase-23-remediation.md). Postfix UID/GID 100/101 und postdrop GID 102 stimmen mit dem bisherigen Image überein. Start, TLS-/AUTH-Prüfung, Queue, Backoff und Wiederherstellung werden weiterhin nativ getestet.
