# ADR-0003: Persistente PostgreSQL-Fachjobs

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.05.06; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Arbeit darf bei Prozessausfall nicht verloren gehen. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

In-Memory-Queue, Redis, allgemeiner Message Broker. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Typisierte Jobs mit Lease, Fencing, SKIP LOCKED, Retrys und Idempotenz.

## Begründung

Persistenz und atomare Annahme mit Fachdatenschreibvorgängen.

## Auswirkungen

Kein Exactly-once-Versprechen, Wiederholung und konkurrierende Worker testen.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/automation-and-audit.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
