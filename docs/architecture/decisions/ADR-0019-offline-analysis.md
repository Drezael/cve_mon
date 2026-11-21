# ADR-0019: Offlinefähige lokale CVE-Auswertung

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.01.05; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Externe Quellen können ausfallen, Sicherheitsdaten müssen lokal verfügbar bleiben. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Internetabhängiges Matching, Löschen alter Quellenstände. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Originale/Revisionen lokal, Matching aus vorhandenem Datenstand, Quellenalter anzeigen.

## Begründung

Vorhandene Daten bleiben nutzbar.

## Auswirkungen

Keine garantierte Aktualität bei Internetausfall, Unknown statt Sicherheit behaupten.

## Spezifikation und Prüfung

[Verbindliche Details](../availability-and-offline.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
