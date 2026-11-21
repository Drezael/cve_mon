# Betrieb ohne ausgehenden Proxy

Der aktive Stack hat acht Container: die drei eigenen Profile `cve-api`,
`cve-processing` und `cve-sources` sowie die unveränderten Originalimages für
Nginx, PostgreSQL, Postfix, n8n und MailHog. Envoy gehört weder zu Compose noch zum
normalen Build-, Start-, Freigabe- oder Statusablauf. Nginx bedient weiterhin
HTTPS und das Dashboard als eingehender Proxy.

## Verbindungen

- Git verbindet sich direkt per HTTPS mit dem konfigurierten CVE-v5-Repository.
  Der bestehende lokale Git-Cache, Commit-Stand und die Verarbeitung der Diffs
  bleiben erhalten. Git verwendet keine Proxy-Umgebungsvariablen oder Benutzer-Hooks.
- HTTPX lädt freigegebene Quelldaten direkt über geprüftes HTTPS. Umgebungsvariablen
  wie `HTTPS_PROXY` werden ignoriert. Explizite Proxy-Konfiguration wird abgewiesen.
  Quellen-, Pfad-, Größen- und Redirect-Prüfungen gelten weiter.
- Postfix verbindet sich direkt mit dem jeweiligen SMTP-Hostname und Port.
  STARTTLS und Zertifikats-/Hostnamenprüfung bleiben verpflichtend. Persönliche
  SMTP-Profile behalten eigene interne Absenderkennungen und SASL-Zugangsdaten,
  auch wenn mehrere Benutzer denselben Mailserver und denselben sichtbaren
  Absender verwenden. TLS-Regeln werden pro Zielserver und Port eindeutig erzeugt.
- n8n bleibt die zentrale Steuerung über die PostgreSQL-Queue und authentifizierte
  interne HTTPS-Aufrufe. Freigegebene externe HTTPS-Verbindungen erfolgen direkt.
- Ansible verwendet weiterhin direkte SSH-Verbindungen zu den konfigurierten Hosts.

`cve_outbound` ist eine gewöhnliche Docker-Bridge mit direktem Ausgang für die
Verarbeitung, Postfix und n8n. Die früheren Zonen `cve_egress_internal` und
`cve_egress_external` entfallen. API, Datenbank und interne HTTPS-Endpunkte behalten
separate interne Netze; öffentliche Hostports besitzt ausschließlich Nginx.
Lokale Namespace-Regeln schützen weiterhin private Datenbank-/Callback-Grenzen.
Die Verarbeitungsgruppe und n8n erhalten direkten ausgehenden HTTPS-Zugriff.
Interne Freigaben berücksichtigen alle gemeinsam genutzten Bridges einschließlich
`cve_outbound`, da Docker-DNS für einen Dienst jede seiner gemeinsamen Adressen
auflösen kann. Das gilt auch für den n8n-Healthcheck und die internen Callbacks.

## Einstellungen und Wiederanlauf

Gespeicherte SMTP-Profile und Empfänger liegen unverändert in PostgreSQL. Ihre
AES-Schlüssel und erzeugten Postfix-Dateien bleiben in den vorhandenen geschützten
Hostverzeichnissen. Alte Proxy-Portzuordnungen werden als historische Daten
beibehalten; der direkte Versand benötigt sie nicht und legt keine neuen an.
SMTP-Aufträge werden erst beansprucht, wenn der native Maildienst bereit ist.
Die Anwendung neuer Einstellungen verwendet ausschließlich `postfix reload`.

Die Migration `00055_direct_outbound` deaktiviert Envoy im aktiven Statuskatalog
und entfernt seine Abhängigkeiten. Historische Beobachtungen und Ereignisse bleiben
in der Datenbank. Die Statusseite zeigt nur die verbleibenden Komponenten.

Für die erstmalige Umstellung sind das neue Anwendungsimage, die Datenbankmigration
und die neuen Netzwerkzuordnungen zusammen bereitzustellen. Vorher Datenbanken,
Konfigurationen und Schlüssel konsistent und verschlüsselt sichern. Danach die
Startcontroller für die bestehenden Namespace-Regeln verwenden. Den bisherigen
Proxycontainer ausschließlich anhand seiner eigenen Projekt-/Servicelabels
entfernen; alte Egress-Netze erst nach Entfernen aller eigenen Endpunkte löschen.
Datenbank- und Mailqueue-Volumes sowie Benutzerkonfigurationen bleiben erhalten.

Frühere Phase-4-Envoy-Dokumente und isolierte Prüfhilfen beschreiben den historischen
Aufbau und werden vom aktuellen Deployment nicht aufgerufen.

## Verifikation

`tests/orchestration/test_direct_network.py` prüft echtes Git-/HTTPS ohne Proxy,
setzt absichtlich unbrauchbare Proxy-Umgebungsvariablen, prüft den n8n-Healthcheck
über die private Dienstverbindung und testet drei persönliche
SMTP-Profile gegen zwei private TLS-Gegenstellen. Zwei Profile teilen sich denselben
Server und sichtbaren Absender, verwenden aber verschiedene Zugangsdaten. Es geht
keine Nachricht an externe Empfänger. `test_settings_persistence.py` prüft weiterhin
Neustart und Container-Neuanlage einschließlich gespeicherter Einstellungen und Schlüssel.
