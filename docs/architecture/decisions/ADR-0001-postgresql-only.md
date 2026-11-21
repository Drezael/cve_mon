# ADR-0001: PostgreSQL als einziges Datenbanksystem

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.05.01; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Fach- und Sicherheitsdaten müssen dauerhaft lokal bleiben. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Weitere DB-Systeme, eingebettete Ersatzdatenbanken. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Ein PostgreSQL-Cluster mit n8n und cve_monitoring; fachliche Schemas und Minimalrollen.

## Begründung

Einheitliche Persistenz und klare Hoheit statt inkonsistenter Doppelhaltung.

## Auswirkungen

Backup-/Restore- und Rollenprüfung zwingend; n8n-Datenbank isoliert.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/overview.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
