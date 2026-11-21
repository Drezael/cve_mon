# Architekturentscheidungen T00.06.01

ADRs enthalten ID, Titel, Status, Datum, Kontext, Problem, Alternativen, Entscheidung,
Begründung, Auswirkungen und Anforderungen. Status: proposed, accepted, superseded, rejected.
Die folgenden accepted-ADRs dokumentieren verbindliche Vorgaben aus Phase 0 Version 1.0,
keine Freigabe laufender Produktivdienste. Entscheidungsdatum: 05.11.2026.
Grundlegende Änderungen erhalten einen neuen ADR; Vorgänger referenzieren und als superseded
markieren, niemals stillschweigend eine akzeptierte Grundentscheidung austauschen.
Redaktionelle Präzisierungen mit unverändertem Inhalt werden im Änderungsbericht vermerkt.

| ADR | Thema |
|---|---|
| [ADR-0001](ADR-0001-postgresql-only.md) | PostgreSQL als einziges Datenbanksystem |
| [ADR-0002](ADR-0002-n8n-orchestration.md) | n8n als zentraler Orchestrator |
| [ADR-0003](ADR-0003-postgres-jobs.md) | Persistente PostgreSQL-Fachjobs |
| [ADR-0004](ADR-0004-transactional-outbox.md) | Transactional Outbox |
| [ADR-0005](ADR-0005-docker-compose.md) | Docker Compose als Deployment-Grundlage |
| [ADR-0006](ADR-0006-nginx-ingress.md) | Nginx als Ingress |
| [ADR-0007](ADR-0007-envoy-egress.md) | Envoy als kontrollierter Egress |
| [ADR-0008](ADR-0008-postfix-queue.md) | Postfix mit persistenter Mailqueue |
| [ADR-0009](ADR-0009-manual-ansible.md) | Manuelle Ansible-Inventarisierung |
| [ADR-0010](ADR-0010-technical-upload.md) | Technischer Upload mit mTLS und Token |
| [ADR-0011](ADR-0011-dashboard-upload.md) | Separater manueller Dashboard-Upload |
| [ADR-0012](ADR-0012-shared-inventory.md) | Gemeinsame Inventarverarbeitung |
| [ADR-0013](ADR-0013-inventory-isolation.md) | Strikte Isolation von Inventaren und Organisation |
| [ADR-0014](ADR-0014-dashboard-groups.md) | Gruppierung ausschließlich über Dashboard-Verwaltung |
| [ADR-0015](ADR-0015-dashboard-order.md) | Manuelle Sortierung ausschließlich über Dashboard-Verwaltung |
| [ADR-0016](ADR-0016-local-users.md) | Lokale PostgreSQL-Benutzerverwaltung |
| [ADR-0017](ADR-0017-totp-admins.md) | TOTP-Pflicht für Administratoren |
| [ADR-0018](ADR-0018-live-status.md) | Statuspage ohne Docker Engine |
| [ADR-0019](ADR-0019-offline-analysis.md) | Offlinefähige lokale CVE-Auswertung |

## Phase-2-Präzisierung

[ADR-0020](ADR-0020-http-ingress-phase02.md) erweitert die ursprüngliche Portgrenze
um den in Phase 2 ausdrücklich vorgesehenen reinen HTTP-Weiterleitungslistener.
Die 19 ursprünglichen Phase-0-Entscheidungen bleiben historisch nachvollziehbar.

[ADR-0021](ADR-0021-postgresql-phase03.md) konkretisiert ab Phase 3 das physische Datenmodell,
Sortierpersistenz, Statuswerte, Standardrollen und Outboxtypen. Er benennt die ersetzten
Darstellungsdetails des Phase-0-Entwurfs ausdrücklich; die ursprünglichen ADRs bleiben lesbar.

[ADR-0022](ADR-0022-envoy-phase04.md) konkretisiert die beauftragte Phase-4-Egress-Topologie,
SMTP-Port 1587, kontrollierte Endpointbindungen und ausschließlich eigene Namespacefilter.

[ADR-0023](ADR-0023-postfix-phase05.md) ergänzt den nativen Postfix-Master mit exakt
begrenzten Prozessrechten, persistenter Queue und echter Smarthost-TLS-Identität.

[ADR-0024](ADR-0024-python-services-phase06.md) konkretisiert die installierbare
technische Python-Basis, den begrenzten API-Reader und kontrollierte Ressourcen.

[ADR-0025](ADR-0025-automation-phase07.md) konkretisiert persistente Jobs/Outbox,
verwaltete Zustandsänderungen, Fencing und geschlossene Dispatcherziele.

[ADR-0026](ADR-0026-authentication-phase08.md) konkretisiert lokale Authentifizierung,
serverseitige Sessions, MFA und die begrenzte Betreiberkontrolle.

[ADR-0027](ADR-0027-authorization-phase09.md) konkretisiert endliches RBAC, explizite
Browser-ACLs, Administratorschutz und kontrollierte private Aktivierung/Recovery.

[ADR-0028](ADR-0028-server-administration-phase10.md) konkretisiert administrative
Server-/Gruppendaten, Primärmitgliedschaften und persistente revisionierte Sortierungen.

[ADR-0029](ADR-0029-inventory-acceptance-phase11.md) konkretisiert die sichere getrennte
Inventarannahme, 202/accepted vor Phase 14 und die versionierten Uploadverträge.

[ADR-0030](ADR-0030-inventory-collection-phase12.md) konkretisiert die lokale Ansible-
Inventarisierung und den gemeinsamen additiven Inventarvertrag 1.1 bei unverändertem 1.0.

[ADR-0031](ADR-0031-ansible-submit-phase13.md) konkretisiert controllerseitigen mTLS-/Token-
Submit, unveränderte Bytes, begrenzte Retries und die Hashgrenze bei reinen Statusabfragen.

[ADR-0032](ADR-0032-inventory-processing-phase14.md) konkretisiert die gefencete
Inventarverarbeitung, unveränderliche Snapshots, den Current-Pointer und die unveränderte
Annahmekompatibilität mit dem vorhandenen Ansible-Submitclient.

[ADR-0038](ADR-0038-external-configuration.md) legt die externe `.env`-Schnittstelle,
versionierte interne Containerwerte, Dashboard-only-Ingress, Let’s Encrypt und
das ausschließlich optionale Mailtest-Profil fest.
