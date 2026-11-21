# ADR-0009: Manuelle Ansible-Inventarisierung

Aktueller Stand: Die frühere externe Ansible-Anbindung ist durch die
repository-eigenen Playbooks und Werkzeuge ersetzt; siehe
[ADR-0038](ADR-0038-external-configuration.md) und
[Ansible-Anleitung](../../../integrations/ansible/README.md).
Der folgende Text dokumentiert die historische Entscheidung.

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: T00.03.01; Phase-0-Konzept Version 1.0, Kapitel 2 und 13.

## Kontext und Problem

Bestehendes externes Ansible-Projekt wird nicht verändert. Abweichende Lösungen würden die vorgegebene Architektur oder Datenhoheit verletzen.

## Betrachtete Alternativen

Automatischer Scan, zusätzlicher Agent, Serveränderungen. Diese Varianten werden nicht neu empfohlen.

## Entscheidung

Operator startet Erfassung und Submit bewusst, Plattform verarbeitet vorhandene Dateien.

## Begründung

Keine nicht autorisierten Veränderungen auf Zielservern.

## Auswirkungen

Kein Inventarscheduler/Agent in dieser Plattform.

## Spezifikation und Prüfung

[Verbindliche Details](../../../contracts/inventory/README.md). Nachweise werden in der Traceability-Matrix und den
Architektur-Abnahmeszenarien zugeordnet; echte Runtime-Nachweise folgen in der jeweiligen
Implementierungsphase. Keine Produktivfunktion wird durch diesen ADR als implementiert ausgegeben.
