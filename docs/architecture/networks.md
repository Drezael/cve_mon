# Netzwerke und Kommunikationsmatrix T00.02.01

Docker-Bridge-Netze auf einem Host, kontrollierte interne DNS-Namen entsprechend den
Komponentennamen. Dies ist ein Konzept, keine Compose-Konfiguration.

| Netzwerk | internal | Vertrauenszone / Zugang |
|---|---|---|
| cve_ingress | false | Nginx, Host-Ports 80 (nur Weiterleitung) und 443; keine Backend-Ports |
| cve_internal | true | Authentifizierte interne APIs, n8n und SMTP-Annahme |
| cve_data | true | PostgreSQL TCP 5432 und ausdrücklich berechtigte Clients |
| cve_egress_internal | true | Importer/Enricher zu Envoy 3128, Postfix zu Envoy 1587 |
| cve_egress_external | false | Nur Envoy zu zugelassenen Zielhosts/-ports |

## Containerzuordnung

| Dienst | Netzwerke |
|---|---|
| cve-nginx | cve_ingress, cve_internal |
| cve-egress-proxy | cve_egress_internal, cve_egress_external |
| cve-postgres | cve_data |
| cve-n8n | cve_internal, cve_data, cve_egress_internal |
| cve-mail-relay | cve_internal, cve_egress_internal |
| cve-api | cve_internal, cve_data |
| cve-dashboard | cve_internal |
| cve-importer | cve_internal, cve_data, cve_egress_internal |
| cve-enricher | cve_internal, cve_data, cve_egress_internal |
| cve-inventory | cve_internal, cve_data |
| cve-matcher | cve_internal, cve_data |
| cve-findings | cve_internal, cve_data |
| cve-reporter | cve_internal, cve_data |
| cve-event-dispatcher | cve_internal, cve_data |
| cve-notification | cve_internal, cve_data |
| cve-service-status | cve_internal, cve_data, cve_egress_internal |

## Verbindliche Kommunikations-ACL

| Quelle | Ziel / Port | Erlaubter Zweck |
|---|---|---|
| Browser / Ansible | Nginx 443 | Separat geprüfte HTTPS-Eingänge |
| Browser | Nginx 80 | Nur GET/HEAD-Weiterleitung auf feste HTTPS-Authority, keine Uploadannahme |
| Nginx | dashboard 8000, api 8443, n8n 5678 | Nur festes Host-/Pfadrouting |
| Dashboard | api 8000 | Menschliche Sitzung und feste API-Aufrufe |
| API | inventory/findings/reporter/status 8000 | Feste interne Methoden, minimale Service-Identität plus Actor |
| n8n | importer/enricher/matcher/findings/reporter/notification 8000 | Zulässige Jobanforderungen, keine Administration |
| Event Dispatcher | n8n 5678 | Authentifizierter Ereigniseingang |
| Importer / Enricher | Envoy 3128 | HTTP/HTTPS zu Quellen-Allowlist |
| Notification | Postfix 25 | Authentifizierte Nachrichteneinlieferung |
| Postfix | Envoy 1587 | Fester SMTP-Tunnel |
| Envoy | Quellen 443, Smarthost 587 | Nur freigegebene IPs/Hosts/Ports; kein allgemeines Routing |
| Services mit DB-Rollen | PostgreSQL 5432 | Nur eigene Datenbank/Rolle gemäß Zugriffsmatrix |
| Statusdienst | HTTP-Healthports, PostgreSQL 5432, Postfix 25 | Nur feste Prüfziele und lesende Protokollchecks |

Alle nicht aufgeführten Wege sind verboten. Netzwerkmitgliedschaft allein erzwingt diese
ACL nicht: gemeinsame Bridges erlauben grundsätzlich Seitwärtsverkehr. Die Infrastrukturphase
muss Host-Firewall/DOCKER-USER beziehungsweise nftables und Dienstauthentifizierung kombinieren,
verbotene Verbindungen testen und keine allgemeine Weiterleitung durch Mehrfach-Netzadapter zulassen.
Insbesondere sind Nginx und Envoy keine Router; keine privilegierten Container, NET_ADMIN,
Host-Netze oder Docker-Socket-Mounts. Nginx bekommt keinen Datenbankzugang.

IPv4 und IPv6 erhalten dieselbe Default-Deny-Politik. Bis gleichwertige IPv6-Filter nachgewiesen
sind, IPv6 in den betroffenen Containerwegen deaktivieren; AAAA-Auflösung darf keinen Bypass öffnen.
`internal: true`, Proxy-Umgebungsvariablen oder DNS-Allowlisting allein sind kein Egress-Schutz.
DNS-Rebinding, private/reservierte Netze, Loopback, Link-local/Metadaten und IPv4-in-IPv6
müssen am tatsächlichen Verbindungsziel kontrolliert werden. Prüfungen dürfen nur feste interne
Service-Namen auflösen; Browserparameter werden nie als Prüfziel oder Resolverziel übernommen.

Phase-4-Konkretisierung: [ADR-0022](decisions/ADR-0022-envoy-phase04.md).
