# Gesamtarchitektur T00.01.04

Verbindliche Quelle ist Phase 0 Version 1.0 (nur lokal archiviert).
Alle Diagramme zeigen die Zielarchitektur; die Anwendung ist noch nicht implementiert.
Es gibt einen PostgreSQL-Cluster mit zwei isolierten Datenbanken, reguläres n8n,
persistente Fachjobs und Transactional Outbox. Kein Redis, Broker oder zusätzliche Workflow-Engine.

## Systemkontext

```mermaid
flowchart LR
    User[Benutzer] -->|HTTPS Sitzung CSRF| Nginx[cve-nginx]
    Ansible[Manuell gestartetes Ansible Submit] -->|HTTPS mTLS API-Token| Nginx
    Nginx --> Dashboard[cve-dashboard]
    Nginx --> API[cve-api]
    Nginx --> N8N[cve-n8n Verwaltung]
    API --> PG[(PostgreSQL)]
    Importer[cve-importer / cve-enricher] --> Envoy[cve-egress-proxy]
    Envoy --> Sources[CVEProject / NVD / CISA KEV / Ubuntu / OSV]
    Postfix[cve-mail-relay] --> Envoy
    Envoy --> SMTP[Fester SMTP-Smarthost]
```

## Komponentenübersicht

```mermaid
flowchart TB
    Dashboard[cve-dashboard] --> API[cve-api]
    API --> PG[(cve_monitoring)]
    N8N[cve-n8n regulär] --> N8NDB[(n8n)]
    N8N -->|Authentifizierte Job-APIs| Workers[Fachdienste]
    Dispatcher[cve-event-dispatcher] -->|Outbox mindestens einmal| N8N
    Workers --> PG
    Inventory[cve-inventory] --> PG
    Matcher[cve-matcher] --> PG
    Findings[cve-findings] --> PG
    Reporter[cve-reporter] --> PG
    Notification[cve-notification] --> PG
    Notification --> Postfix[cve-mail-relay]
    Status[cve-service-status] -->|Direkte feste Prüfziele| Workers
    API --> Status
```

[Verantwortungen](responsibilities.md), [Datenflüsse](data-flow.md),
[Netzwerke](networks.md), [DB-Matrix](../database/access-matrix.md).
