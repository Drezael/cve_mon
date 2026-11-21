# ADR-0008: Postfix mit persistenter Mailqueue

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.02.03; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Externe Mailzustellung kann zeitweise ausfallen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Direktes SMTP aus jedem Fachservice. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Nur Notification→Postfix; fester Envoy-TCP-Tunnel, STARTTLS prüft externen Smarthost.

## Begründung

Persistente Warteschlange und klare Zustellgrenze.

## Auswirkungen

Queue begrenzt, Endzustellung nicht bei SMTP-Annahme garantiert.

## Spezifikation und Prüfung

[Verbindliche Details](../egress.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
