# ADR-0005: Docker Compose als Deployment-Grundlage

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.02.01; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Self-hosted Betrieb benötigt nachvollziehbare Infrastruktur. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Zusätzliche Cloud-Orchestrierung oder Host-Direktdienste. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Docker Compose mit fünf vorgegebenen Netzen und persistenten Volumes.

## Begründung

Verbindliche Vorgabe ohne zusätzliche Plattformabhängigkeit.

## Auswirkungen

Echte Compose-Dateien und Container erst ab Phase 2.

## Spezifikation und Prüfung

[Verbindliche Details](../networks.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
