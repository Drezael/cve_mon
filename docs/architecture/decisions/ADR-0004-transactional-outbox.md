# ADR-0004: Transactional Outbox

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.05.06; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Datenänderung und Ereignis dürfen nicht auseinanderfallen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Nicht atomare Publish-nach-Commit-Logik. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Outbox-INSERT im Fachcommit; Dispatcher liefert mindestens einmal an n8n.

## Begründung

Keine verlorene Folgeverarbeitung zwischen zwei Systemen.

## Auswirkungen

Consumer deduplizieren Event-ID und Typ; Dispatcher ändert keine Nutzdaten.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/automation-and-audit.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
