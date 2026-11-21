# Datenflüsse T00.01.04

Systemkontext und Containerübersicht stehen in [overview.md](overview.md).

## CVE-Import

```mermaid
flowchart LR
    N8N[cve-n8n] -->|Job-API| Importer[cve-importer]
    Importer -->|HTTPS via Envoy| Source[CVEProject]
    Importer -->|Original und Revision plus Outbox atomar| PG[(PostgreSQL)]
    PG --> Dispatcher[cve-event-dispatcher]
```

CVE-ID/Revision und Quellenhash deduplizieren; Rohdaten lokal halten; Änderungen erzeugen cve.updated.

## Herstellerdatenanreicherung

```mermaid
flowchart LR
    N8N[cve-n8n] --> Enricher[cve-enricher]
    Enricher --> Envoy[cve-egress-proxy]
    Envoy --> Sources[NVD / CISA / Ubuntu / OSV]
    Enricher -->|Quellenspezifische Revision| PG[(PostgreSQL)]
```

Original und Ergänzung bleiben unterscheidbar; Retrys respektieren Quoten. Kein Internet im Matcher.

## Technischer Inventar-Upload

```mermaid
flowchart LR
    Ansible[Manuelles Submit] -->|mTLS und Token| Nginx[Technischer Nginx-Host]
    Nginx -->|Geschützter Identitätsnachweis| API[cve-api api_ingest]
    API -->|Snapshot Receipt Job Outbox atomar| PG[(PostgreSQL)]
```

Zertifikat und Token gehören zum selben technischen Principal mit serverbezogenem Submit-Recht; unbekannte Server werden abgelehnt.

## Dashboard-Datei-Upload

```mermaid
flowchart LR
    User[Benutzer wählt JSON-Datei] --> Dashboard[Dashboard und gleicher Origin]
    Dashboard -->|Sitzung CSRF Objektberechtigung| API[cve-api api_ingest]
    API -->|Identitätsabgleich und gleicher Annahmevertrag| PG[(PostgreSQL)]
```

Multipart enthält ausschließlich server_id und file; Herkunft dashboard_file wird serverseitig vergeben.

## Gemeinsame Inventarverarbeitung

```mermaid
flowchart LR
    PG[(Persistenter inventory.process Job)] --> Inventory[cve-inventory]
    Inventory -->|Normalisierung und inventory.processed| PG2[(PostgreSQL)]
    PG2 --> Dispatcher[cve-event-dispatcher]
    Dispatcher --> N8N[cve-n8n]
    N8N --> Matcher[cve-matcher]
```

Beide Annahmewege erzeugen denselben Jobtyp. Teil-/Fehlinventare liefern keine negativen Abwesenheitsbeweise.

## Matching und Findings

```mermaid
flowchart LR
    Trigger[Neues Inventar oder neue CVE-Revision] --> Matcher[cve-matcher]
    Matcher -->|Lokale Quellen und Snapshot| PG[(PostgreSQL)]
    Matcher -->|Matching-Ergebnisse| Results[(matching.results)]
    N8N[cve-n8n] --> Findings[cve-findings]
    Results --> Findings
    Findings --> History[(findings mit Historie und Outbox)]
```

Neue CVEs erfordern keinen neuen Upload. Ubuntu-Versionsvergleiche berücksichtigen Epoch und Distributionsrevision sowie Hersteller-Backports.

## Alarmierung und E-Mail

```mermaid
flowchart LR
    Outbox[(finding.changed)] --> Dispatcher[cve-event-dispatcher]
    Dispatcher --> N8N[cve-n8n]
    N8N --> Notification[cve-notification]
    Notification --> Postfix[cve-mail-relay Queue]
    Postfix --> Envoy[cve-egress-proxy TCP]
    Envoy --> SMTP[Smarthost STARTTLS]
```

Ereignis- und Empfänger-ID deduplizieren. SMTP-Annahme bedeutet nicht garantierte Endzustellung; verlorene Quittung kann Duplikate erzeugen.

## Administrative Gruppenänderung

```mermaid
flowchart LR
    User[Autorisierter Benutzer mit MFA] --> Dashboard[cve-dashboard]
    Dashboard -->|Sitzung CSRF If-Match| Admin[cve-api dashboard_admin]
    Admin -->|Mitgliedschaft Primärgruppe Sortierung und Audit atomar| PG[(PostgreSQL)]
```

Keine Kante von Inventarereignissen, Matcher oder n8n in diesen schreibenden Kontext. Gruppenwechsel ändern dynamische Objektberechtigungen, nicht das Inventar.

## Statuspage-Abfrage

```mermaid
flowchart LR
    User[Angemeldeter Benutzer] --> Dashboard[cve-dashboard]
    Dashboard --> API[cve-api prüft deployment:status:read]
    API --> Status[cve-service-status]
    Status -->|Neue parallele direkte Checks| Targets[Feste HTTP PostgreSQL SMTP Ziele]
    Targets --> Status
    Status -->|Prüfzeitpunkt Teilfehler no-store| API
```

Jeder Aufruf prüft neu, begrenzt auf feste Ziele. Die integrierte Seite hängt selbst von Dashboard/API/Auth ab; keine Docker-Abfrage.
