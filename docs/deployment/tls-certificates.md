# TLS-Zertifikate

Das Dashboard verwendet eine einzige öffentliche Domain aus `DASHBOARD_DOMAIN`.
Interne TLS-Identitäten und die interne Client-CA werden getrennt verwaltet und
sind keine zusätzlichen öffentlichen Let’s-Encrypt-Zertifikate.

## Serverbetrieb

Es gibt zwei Eingangswege:

- **Automatisch:** `LETSENCRYPT_ENABLED=true` aktiviert den optionalen
  Certbot-Container mit Cloudflare DNS-01. Er stellt das Erstzertifikat aus und
  prüft regelmäßig auf fällige Erneuerung. Dafür werden Kontaktadresse,
  ausdrückliche Zustimmung und ein auf die DNS-Zone beschränkter API-Token benötigt.
  Kein HTTP-Challenge-Verfahren, kein zusätzlicher öffentlicher Port.
  [Vollständige Einrichtung](letsencrypt-cloudflare.md).
- **Extern:** Bei `LETSENCRYPT_ENABLED=false` enthält `TLS_DIR` die extern
  gepflegten Dateien `fullchain.pem` und `privkey.pem`. Die üblichen Certbot-
  Symlinks nach `archive/` bleiben unterstützt. Ausstellung und Erneuerung
  übernimmt in diesem Fall ein externes ACME-Werkzeug.

Die Dienste erhalten minimale read-only Snapshots. Der Preflight prüft
Vertrauenskette, Dashboard-Namen, Verwendungszweck, Schlüsselpaar und mindestens
24 Stunden Restgültigkeit. Entwicklungsschlüssel werden in Produktion abgewiesen.

## Lokale Entwicklung

`cve_mon start` erzeugt bei einer neuen Entwicklungsinstanz die benötigten
Testzertifikate automatisch. Die Ablage wird aus `TLS_DIR` und `SECRETS_BASE`
abgeleitet. Vorhandene Schlüssel werden weiterverwendet und nicht bei jedem
Start ersetzt. Die Entwicklungspfade sind ignoriert und gehören nicht in Git.

Eine lokale Test-CA ist kein öffentlich gültiges Zertifikat. Für den Zugriff die
Testdomain passend auflösen und die Test-CA auf dem Entwicklungsclient gezielt
verwenden. Es wird kein Systemvertrauen automatisch verändert. Automatisches
öffentliches Let’s Encrypt ist im Entwicklungsmodus deaktiviert und wird bei
Aktivierung abgewiesen.

## Übernahme und Rotation

Der Hostcontroller prüft die Zertifikatsquelle alle 60 Sekunden. Nach erfolgreicher
Validierung übernimmt er das neue Paar, prüft `nginx -t` und lädt Nginx neu.
Bei einem Fehler bleibt das bisherige aktive Bundle erhalten. Verzeichnis-Bind-
Mounts erlauben Dateiaustausch ohne einen Containerneustart.

Bei automatischem Cloudflare-Betrieb müssen Certbot und Hostcontroller laufen:
Certbot erneuert die Quelldateien, der Hostcontroller übernimmt sie in den
Dienst-Snapshot. Bei externem Betrieb muss die externe Erneuerung funktionieren.

Datensicherung umfasst die öffentlichen Zertifikatsschlüssel, ACME-Kontodaten,
private Instanzkonfiguration und interne Schlüssel. Ein CA-Wechsel verlangt eine
geplante Umstellung der betroffenen Vertrauensbeziehungen.

Weitere Informationen: [Bedienungsanleitung](../bedienungsanleitung.md),
[Zertifikatsrotation](../operations/certificate-rotation.md).
