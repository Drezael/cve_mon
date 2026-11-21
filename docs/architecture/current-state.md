# Bestandsaufnahme T00.01.01

Projektwurzel: `/home/gerald/Documents/cve_mon`. Stand: 05.11.2026 vor Nachholung von Phase 0.
Git ist initialisiert (main), ohne Commits/Remote. Sämtliche Projektdateien sind noch unversioniert.
Phase 1 wurde vorab umgesetzt: Entwicklungsstruktur, Python-3.12-Umgebung, Hash-Lock,
Ruff, Mypy, 51 Pytest-Fälle, Validator, Secret-Prüfung, Make und CI-Workflow.
Vorhanden sind Bereichs-READMEs und Entwicklungsdokumentation; keine produktiven
Dienste, Compose-Dateien, Datenbankmigrationen oder Infrastrukturkonfigurationen.

Nachgereicht wurde `docs/history/plans/phase_00.md` Version 1.0 (33 Aufgaben). Beide Original-
Phasenkonzepte bleiben unverändert. Gesamtkonzept 3.12 und übergeordneter Entwicklungsplan
1.2 liegen weiterhin nicht separat vor; die in den Phasenkonzepten wiedergegebenen Vorgaben
bilden die verfügbare verbindliche Grundlage. Ein Abgleich mit den separaten Originalen
bleibt eine dokumentierte Voraussetzung für spätere Umsetzung.

Es fehlen zu Beginn: Komponentenkatalog, Datenflüsse, Netzwerk-/Sicherheitsmodell,
Inventarschema und Beispiele, OpenAPI, logisches Datenmodell, Rechte, ADRs und Abnahmeszenarien.
Die bestehenden READMEs widersprechen der Architektur nicht, enthalten aber veraltete
Hinweise auf fehlende Phase-0-Ergebnisse. Der Phase-1-Validator prüft bislang nur die
Definition von Schemas, keine Inventarbeispiele und keine OpenAPI-Semantik.

Folge: Phase-0-Spezifikationen vollständig erstellen; danach diese Hinweise, die
Pflichtstruktur, Entwicklungsabhängigkeiten, Vertragsprüfungen und Phase-1-Abnahme aktualisieren.
Keine Änderung am externen Ansible-Projekt, keine fachliche Implementierung und kein Deployment.

Aktualisierung 06.11.2026: Die vorstehende Bestandsaufnahme ist historisch. Phase 2 und Phase 3
sind inzwischen implementiert. Aktueller Datenbanknachweis: [Phase-3-Abnahme](../development/phase-03-acceptance.md).
