# ADR-0002: n8n als zentraler Orchestrator

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.01.02; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Zeitpläne und Folgeaktionen benötigen Orchestrierung, keine neue Workflow-Engine. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Eigene Engine, zusätzlicher Broker, Redis-Queue-Modus. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

n8n regulär ausführen; Fachlogik und Jobs verbleiben in Diensten/PostgreSQL.

## Begründung

Bestehende Architektur wird beibehalten.

## Auswirkungen

n8n hat keinen Fachdatenbankzugriff und keine Gruppenverwaltung.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/automation-and-audit.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
