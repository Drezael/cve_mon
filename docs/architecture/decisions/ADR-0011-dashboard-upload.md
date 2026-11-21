# ADR-0011: Separater manueller Dashboard-Upload

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.04.03; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Menschen benötigen vorhandene Datei ohne technische Zertifikatsidentität. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Technische Token in Browsern, Upload als Administrationsimport. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Sitzung, CSRF, Datei-/Zielserverabgleich und Objektberechtigung.

## Begründung

Getrennte Benutzer- und technische Sicherheitsgrenzen.

## Auswirkungen

10-MiB-Dateilimit; Herkunft nur aus vertrauenswürdiger Annahme.

## Spezifikation und Prüfung

[Verbindliche Details](../../api/authentication-boundaries.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
