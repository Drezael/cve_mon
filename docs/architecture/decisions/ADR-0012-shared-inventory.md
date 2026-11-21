# ADR-0012: Gemeinsame Inventarverarbeitung

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.03.03; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Zwei Annahmewege dürfen keine abweichende fachliche Wahrheit erzeugen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Zwei unabhängige Normalisierungen. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Gleiches Schema, gleicher Annahmeprozess, inventory.process und cve-inventory.

## Begründung

Einheitliche Historisierung und Idempotenz.

## Auswirkungen

partial/failed liefern keine negativen Abwesenheitsbeweise.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/inventory.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
