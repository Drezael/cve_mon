# ADR-0014: Gruppierung ausschließlich über Dashboard-Verwaltung

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.04.04; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Organisatorische Zuordnung ist eine menschliche Verwaltungsentscheidung. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Automatische Zuordnung durch CVEs, Matching oder n8n. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Explizite Admin-Operationen mit Sitzung/CSRF/MFA, Berechtigung und Audit.

## Begründung

Kein technischer Workflow erhält implizite Organisationshoheit.

## Auswirkungen

Primärgruppe muss Mitgliedschaft sein; parallele Änderungen versioniert.

## Spezifikation und Prüfung

[Verbindliche Details](../../database/server-and-groups.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
