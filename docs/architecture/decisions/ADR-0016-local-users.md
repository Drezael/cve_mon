# ADR-0016: Lokale PostgreSQL-Benutzerverwaltung

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.05.05; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Offlinefähigkeit und kontrollierte Kontolebenszyklen sind verbindlich. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Öffentliche Registrierung, feste Standardzugänge. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Lokale Konten, Argon2id, geschützte Verifikatoren, serverseitiger Sitzungswiderruf.

## Begründung

Keine zusätzliche Benutzer-Cloud-Abhängigkeit.

## Auswirkungen

Letzten aktiven Administrator atomar schützen; Secrets nicht in normalen Responses.

## Spezifikation und Prüfung

[Verbindliche Details](../../security/authentication.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
