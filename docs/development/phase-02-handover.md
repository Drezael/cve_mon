# Phase-2-Übergabe

Status: completed, lokale Entwicklungsinfrastruktur freigegeben. Kein Produktivdeployment;
Host-Firewall-/Egress- und produktiver PKI-/Widerrufsnachweis bleiben verbindliche Betriebsfreigaben.
Nginx 1.30.6/Alpine3.24 ist auf offiziellen Indexdigest
sha256:dc06c17afbc08d6fe9fbe48159aa81459da2b56baddddc45002f1a68ef77e256 gepinnt.
Compose verwendet absichtlich die reine nginx@sha256-Referenz; Version/Herkunft wurden am Image geprüft.

| Folgephase | Verbindliche Integration |
|---|---|
| Phase 3 PostgreSQL | cve_data internal, eigene Persistenz/DB-Rollen/Health, niemals Hostport; aktuell nur Netzwerkdefinition |
| Phase 4 Envoy | cve_egress_internal/external; geschützter interner Statuszugang gemäß Phase 0 zusätzlich abgleichen; keine direkte Backend-Internetfreigabe |
| Phase 5 Postfix | Persistente Queue, fester SMTP-TCP-Tunnel über Envoy, externe Smarthost-TLS-Identität |
| Phase 6 Python | Interne Health-/Readiness-Standards, zugewiesene Minimalnetze und DB-Rollen; keine zusätzlichen offenen Ports |
| Phase 8 Authentifizierung | Gesperrte Adminrouten erst nach Sitzung/CSRF/MFA/Objektprüfung aktivieren, dedizierte Dienstidentitäten/PKI |
| Phase 11 Inventar | Technischen mTLS-Weg mit Token/Serverbindung, vertrauensgebundenem Nginx-Peer, gemeinsamer Verarbeitung und Gruppenisolation aktivieren |
| n8n-Integration | Regulärer Modus, restriktiver UI-Zugang; 503 erst nach Backendprüfung ersetzen; WebSocket-Upgrade nur auf expliziter Route mit eigener Headerpolitik |
| Phase 20 Dashboard | Gleicher Origin für API-/Datei-Upload, Sitzung/CSRF; finale CSP anhand tatsächlicher UI prüfen |
| Phase 22 Statuspage | Direkt http://cve-nginx:8081/healthz aus cve_internal; keine Docker Engine, kein Socket; Nginx-Health ist keine Backend-Readiness |

Beide Uploadwege nehmen aktuell nichts fachlich an. Die API-Routenskelettprüfung ist keine
Payload-/Methoden-/Berechtigungsprüfung des späteren Backends. Keine Identität allein anhand
beliebiger HTTP-Header akzeptieren. Native Nginx-Request-IDs sind opaque Ingresskennungen;
die API normalisiert/erzeugt ihren UUID-Korrelationsbezeichner gemäß API-Vertrag und bindet
Ingresskennungen ausschließlich als geprüfte Trace-Metadaten ein.

Sichere Template-/TLS-Snapshots, Read-only-Mounts, UID/Timeout-/Limitgrenzen und Logschutz
bei Integration beibehalten. Hostregeln/DNS-Rebinding/IPv6 und Dienstauthentifizierung separat
nachweisen. Keine automatische Änderung am externen Ansible-Projekt.

ADR-0020 gleicht den expliziten Phase-2-Port-80-Redirect mit Phase 0 ab. Separate Originale
Gesamtkonzept 3.12/Entwicklungsplan 1.2 bleiben nachzureichen/abzugleichen; die verfügbaren
Phasenkonzepte waren Grundlage. Gehostete GitHub-CI nach autorisiertem Commit/Push kontrollieren.
Phase 3 wurde nicht begonnen. [Betriebsanleitung](../deployment/docker-compose.md).
