# ADR-0015: Manuelle Sortierung ausschließlich über Dashboard-Verwaltung

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.05.02; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Inventarstände dürfen die sichtbare manuelle Organisation nicht umordnen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Sortierwerte aus Upload oder Matching. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Globale Gruppen- und bereichsbezogene Serverreihenfolge mit eigenem Versionsaggregat.

## Begründung

Persistente, nachvollziehbare manuelle Reihenfolge.

## Auswirkungen

Vollständige autorisierte Permutation und If-Match; kein Inventory-Write.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/server-and-groups.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.

Phase-3-Konkretisierung: [ADR-0021](ADR-0021-postgresql-phase03.md) legt die kanonischen
Positionen an Gruppen/Mitgliedschaften und abgeleitete Order-Sichten fest. Keine zweite
persistierte Wahrheit; fachliche Hoheit und Versionsaggregate bleiben erhalten.
