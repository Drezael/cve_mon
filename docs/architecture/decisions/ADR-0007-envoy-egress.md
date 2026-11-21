# ADR-0007: Envoy als kontrollierter Egress

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.02.03; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Quellenzugriffe dürfen keinen allgemeinen Internetzugang eröffnen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Direkter Backend-Egress oder freie CONNECT-Ziele. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Client-/Host-/Port-Allowlist, DNS-/Adressprüfung und zusätzlicher Host-Egressfilter.

## Begründung

Kontrollierte Kommunikation und Schutz interner Netze.

## Auswirkungen

IPv4/IPv6 und Redirect-/Rebinding-Bypass testen.

## Spezifikation und Prüfung

[Verbindliche Details](../egress.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
