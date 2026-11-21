# ADR-0006: Nginx als Ingress

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.02.02; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Unterschiedliche Identitätsgrenzen müssen getrennt bleiben. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Gemeinsamer optionaler mTLS-Uploadhost. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Getrennte Dashboard/API/Submit/n8n-Hosts, Submit strikt mTLS, vertrauensgebundene Header.

## Begründung

Technische Identität kann Browseradministration nicht ersetzen.

## Auswirkungen

TLS-Weitergabe und externe Header-Spoofs mit realen Komponenten prüfen.

## Spezifikation und Prüfung

[Verbindliche Details](../ingress.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
