# ADR-0017: TOTP-Pflicht für Administratoren

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.04.05; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Administrative Rechte benötigen stärkeren Nachweis. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Nur Passwort, optionale Admin-MFA. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Bestätigte TOTP-Methode vor Adminrechten, Replay-Schutz und geschützte Recovery.

## Begründung

Begrenzt Risiko gestohlener Passwörter.

## Auswirkungen

Verschlüsselungsschlüssel außerhalb DB; Recovery/Bootstrap auditieren.

## Spezifikation und Prüfung

[Verbindliche Details](../../security/authentication.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
