# Statuspage-Architektur

Erweiterung des bestehenden API-/PostgreSQL-/Dashboard-Stacks. Der Collector läuft mit separater status_probe-Identität und verwendet das bestehende gefencte Jobruntime. Keine weitere Datenbank, kein Redis/Broker, kein Container, Docker-Socket, Host-PID oder öffentlicher Administrationsport. Nur Statusmessungen, Historien, Wartungsmetadaten und explizite Outbox-Alarmereignisse werden geschrieben. Fachzustandsmaschinen bleiben erhalten.

Die lokalen Envoy-/Postfix-Adapter besitzen jeweils nur ihren eigenen aggregierten Beobachtungsmount; API liest den gemeinsamen Wurzelmount read-only. Es werden keine privaten Zertifikate oder Queueverzeichnisse zusätzlich in die API eingebunden. HTTP-Probes verwenden codeeigene Adressen, feste Pfade, keine Redirects, keine Proxy-Umgebungsvariablen und verifiziertes TLS.

Details: [Katalog](../status/service-catalog.md), [Collector](../status/collector.md), [Zugriff](../status/api.md), [Sicherheit](../security/statuspage-security.md).
