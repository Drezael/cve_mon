# ADR-0018: Statuspage ohne Docker Engine

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.02.05; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Status soll tatsächliche Dienste prüfen, keine Container verwalten. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Docker-Socket/Engine API, gecachter Zustand als live. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Direkte feste HTTP-/DB-/SMTP-Checks je Aufruf, begrenzte Parallelität und no-store.

## Begründung

Kleinere Privilegien und ehrlichere Dienstzustandsaussage.

## Auswirkungen

Seite hängt selbst von Dashboard/API/Auth ab; Teilfehler isolieren.

## Spezifikation und Prüfung

[Verbindliche Details](../statuspage.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
