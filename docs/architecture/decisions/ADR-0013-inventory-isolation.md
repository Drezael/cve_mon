# ADR-0013: Strikte Isolation von Inventaren und Organisation

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.01.03; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Uploaddaten sind untrusted und dürfen Berechtigungsgrenzen nicht verändern. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Gruppenfelder in Metadaten, Trigger aus Inventaren. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Geschlossene Objekte auf jeder Ebene; DB-Deny für administrative Tabellen.

## Begründung

Sicherheitsinvariante ist in Vertrag, Hoheit und Grants verankert.

## Auswirkungen

API-Ingest und Processor schreiben keine Serverstammdaten/Gruppen/Sortierung.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/access-matrix.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
