# Dienste

Der [Komponentenkatalog](../docs/architecture/components.md) beschreibt die vorgesehenen
Verantwortlichkeiten. Bis Phase 19 sind API, Event Dispatcher, Inventory Processor,
CVE Importer, CVE Enricher, Matcher, Finding Worker und Notification Worker als Python-Dienste implementiert. Zusammen mit
PostgreSQL, Nginx, Envoy, Mail Relay und n8n laufen dreizehn eigene Compose-Dienste.

Die gemeinsame Basis ist [cve_common](../docs/architecture/python-services.md). Jeder Worker verwendet
eine eigene PostgreSQL-Identität sowie die bestehenden Jobs und Leases. Administrative
Writes führt ausschließlich cve-api im autorisierten Dashboard-Kontext aus. Der Matcher
hat keine Finding-Schreibrechte und keinen externen Netzwerkzugriff.

Reporting, Dashboard und Statuspage folgen gemäß
Entwicklungsplan; vorhandene Verzeichnisnamen stellen keine weiteren aktiven Container dar.
[Matcher](matcher/README.md), [aktueller Stand](../docs/development/development-status.md).

[Finding Worker](findings/README.md), [Finding-Architektur](../docs/architecture/finding-management.md).

[Notification Worker](notification/README.md), [n8n](../docs/n8n/architecture.md).
