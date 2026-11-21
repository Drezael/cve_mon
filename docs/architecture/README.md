# Architekturgrundlage

Verbindliche, versionierte Phase-0-Ergebnisse:

- [Übersicht](overview.md), [Komponentenkatalog](components.md), [Datenhoheit](responsibilities.md)
- [Datenflüsse](data-flow.md), [Ausfälle und Offlinebetrieb](availability-and-offline.md)
- [Netzwerke](networks.md), [Ingress](ingress.md), [Egress](egress.md), [interne Grenzen](internal-trust.md)
- [Statuspage](statuspage.md), [ADRs](decisions/README.md)
- [Inventarvertrag](../../contracts/inventory/README.md), [OpenAPI](../../contracts/api/openapi.yaml)
- [Datenmodell](../database/overview.md), [Berechtigungen](../database/access-matrix.md)
- [Bedrohungsmodell](../security/threat-model.md), [Abnahmeszenarien](../testing/architecture-acceptance-scenarios.md)
- [Phase-0-Abnahme](../development/phase-00-acceptance.md), [Übergabe](../development/phase-00-handover.md)

Grundlage: Originalkonzepte Phase 0 (nur lokal archiviert) und
Phase 1 (nur lokal archiviert). Gesamtkonzept 3.12 und Entwicklungsplan 1.2 sind
weiterhin nicht als separate Originale vorhanden; ihre in den Phasenkonzepten enthaltenen
Vorgaben wurden übernommen. Die Spezifikationen behaupten keine produktive Implementierung.

Aktueller Infrastrukturstand: [Phase-2-Abnahme](../development/phase-02-acceptance.md).
ADR-0020 dokumentiert den erlaubten reinen HTTP-Weiterleitungseingang.
