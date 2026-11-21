# Übergabe Phase 4 → Phase 5

Envoy ist implementiert: offizielles 1.40.2-Digest, 3128 HTTP/CONNECT, 1587 fester SMTP-TCP-Proxy,
9901 geschütztes GET-Health/Metriken und ausschließlich privater Unix-Adminsocket. Kernelguard
prüft echte Zieladressen, getrennte Clientbindungen und direkten Egress. Keine Runtime-Capabilities,
kein Hostport, kein zusätzlicher Produktionsproxy/DNS-Dienst und keine SMTP-Credentials in Envoy.

[Abnahme](phase-04-acceptance.md), [Status](phase-04-status.md),
[Betrieb](../deployment/envoy.md), [SMTP-Vertrag](../security/smtp-proxy-security.md).

## Änderungen an vorhandenen Phasen

- Phase 0: ADR-0022 und Netzwerk-/Servicevertrag gleichen Envoys ausschließlich zwei Netze,
  SMTP1587 sowie spätere Egressnetzmitgliedschaft für n8n/Status ab. Keine Originalkonzepte verändert.
- Phase 1: eigener egress-Pytestmarker, Importlib-Testmodus gegen gleiche Modulnamen in getrennten
  Testsuiten, Make-/Wrapper-/CI-/Repositoryprüfungen ergänzt. Keine zusätzlichen Pythonpakete.
- Phase 2: Compose erweitert nur Envoy; Nginx startet weiterhin separat, bestehende Ingress- und
  Netzprüfungen werden erneut mit dem erweiterten Modell ausgeführt. Keine Host-Firewallmutation.
- Phase 3: PostgreSQL-Konfiguration, Migrationen, Datenvolume und Rollen bleiben unverändert;
  seine echten Rechte-/Persistenz-/Restoretests werden als Regression erneut ausgeführt.

## Verbindliche Anschlussregeln

Phase 5 legt einen echten Smarthost explizit fest, aktiviert dessen SMTP-Policy und bindet ausschließlich
mail-relay. Postfix bleibt für STARTTLS, externe CA-/Namensprüfung trotz internem Nexthop,
AUTH-Credentials und persistente Queue verantwortlich. Keine direkte SMTP-Alternative.
Der Testserver ist keine produktive Relaykonfiguration.

Phase 6 startet Clients hinter demselben kontrollierten Netzwerk-Freigabebarrier: Nicht-Root,
cap_drop ALL, ausschließlich erforderliche interne Netze, expliziter Proxy und kein Fallback.
Benötigte interne API-/DB-Peers vor Start port-/dienstgenau in den Client-Namespacefilter aufnehmen
und testen; nicht pauschal private Netze freischalten. Clients vor Recreate bei gestopptem Proxy
neu binden. Dienstlabels allein verleihen keine Berechtigung; aktuelle Container/IP/MAC prüfen.

Phase 15/16 pinnen tatsächliche Importverfahren, URLs/Redirect-/Downloadhosts und Datenversionen.
Zusätzliche Hosts nur einzeln prüfen/freigeben. HTTPS-Pfade und innere Methoden bleiben Aufgabe
der Adapter, da CONNECT kein TLS-MITM ist. DNS-/SSRF-/CIDR-Schutz bei Änderungen vollständig prüfen.

Phase 19 prüft n8ns tatsächliche Proxyvariablenunterstützung und benötigte Zielregeln; standardmäßig
ist kein externer n8n-Host freigegeben. Phase 22 bindet nur den Statusdienst an GET /healthz und
/metrics; keine generische Admin-URL, Docker-Socket- oder SMTP-Relayberechtigung.

Betrieb benötigt Linux nsenter/nft/ip plus autorisierten Operatorzugang für eigene Namespaces.
Ein nackter Containerneustart öffnet nichts mit einem alten Guard: `envoy-up` rekonstruiert die
Schutzkette geprüft. Nach Abschluss bleibt nur der normale sichere Default-Deny-Envoy aktiv;
eigene Test-/Restoreumgebungen werden entfernt, fremde Ressourcen nicht verändert.
