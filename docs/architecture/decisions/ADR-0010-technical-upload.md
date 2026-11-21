# ADR-0010: Technischer Upload mit mTLS und Token

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.04.02; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Zertifikat allein reicht nicht für serverbezogene Fachberechtigung. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Nur Token oder frei behauptete Zertifikatsheader. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Pflicht-mTLS UND cert-/servergebundener inventory:submit-Token.

## Begründung

Transportidentität und minimale Fachautorisierung ergänzen sich.

## Auswirkungen

Kanonisierung/Idempotenz, gleiche inventory_id kanalübergreifend, keine Gruppenrechte.

## Spezifikation und Prüfung

[Verbindliche Details](../../../contracts/inventory/rejection-cases.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
