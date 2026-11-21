# Coding-Standards

## Sprache und Struktur

Python 3.12 ist die Entwicklungsbasis. Python-Dateien, Funktionen und Variablen verwenden
`snake_case`, Klassen `PascalCase`, Konstanten `UPPER_SNAKE_CASE`. Dateien erhalten
sprechende Namen. Verantwortlichkeiten liegen in den dokumentierten Projektbereichen;
spätere Dienste werden als eigene Pakete eingeführt und in Mypy aufgenommen.
Keine leeren Python-Pakete oder nicht implementierten Dienste anlegen.

Ruff formatiert mit 100 Zeichen Zeilenlänge, prüft Importe, ungenutzte Namen sowie
E/F/I/B/UP/SIM-Regeln. Neue Funktionen erhalten vollständige Typannotationen und kurze
Docstrings für Zweck und relevante Nebenwirkungen. Mypy läuft strikt auf Skripten und Tests.
PyYAML und jsonschema besitzen explizite Typ-Stubs; fehlende Imports werden nicht global ignoriert.
Die direkte Skriptausführung ergänzt den Repository-Suchpfad für gemeinsame Hilfen.
Mypy ordnet diese Module über `explicit_package_bases` eindeutig zu. Globale Lint- oder Typausnahmen sind nicht eingerichtet.

## Fehler, Logging und Konfiguration

Erwartbare Fehler gezielt abfangen, Ursachen mit Dateiname melden und mit Fehlerstatus beenden.
Keine pauschal verschluckten Ausnahmen. Skripte verwenden verständliche Standardausgaben;
spätere Dienste verwenden strukturiertes Logging ohne Tokens, Passwörter oder Inventarinhalte.
Konfiguration wird explizit eingelesen; lokale Werte gehören in ignorierte Dateien,
unkritische dokumentierte Vorlagen in `.env.example`. Keine Zugangsdaten im Quellcode.
Subprozesse erhalten Argumentlisten ohne Shell-Interpolation. YAML nur sicher laden.

## API- und Dienstkonventionen

API-Verträge und Datenmodelle werden aus Phase 0 übernommen, nicht hier erfunden.
Spätere FastAPI-Dienste grenzen ihre Verantwortung klar ab und vermeiden unnötige Querverbindungen.
Serverseitige Autorisierung ist für jede betroffene Operation erforderlich. Datenbankzugriffe
verwenden kontrollierte PostgreSQL-Transaktionen und definierte Fehlerbehandlung.
Technischer Inventar-Upload und Dashboard-Datei-Upload bleiben getrennt; gemeinsame Verarbeitung
ändert keine Gruppen. Gruppenmitgliedschaften, Primärgruppen und Sortierungen gehören allein
in die autorisierte Dashboard-Administration. Statuspage ohne Docker Engine API.

## Tests und Sicherheitsregeln

Tests heißen `test_*.py`, Funktionen `test_*`. Gemeinsame Fixtures stehen in `tests/conftest.py`.
Positive Fälle und relevante Fehlerfälle prüfen, ohne produktive Dienste oder Daten zu verändern.
Fehlerexperimente erfolgen in temporären Verzeichnissen. Synthetische Secret-Testdaten erst zur
Laufzeit zusammensetzen; keine echten Zugangsdaten als Fixtures verwenden.

Vor Übergabe `make check` ausführen. Neue YAML-/JSON-Dateien werden automatisch geprüft;
JSON-Schemas heißen `*.schema.json` oder enthalten `$schema`. Neue Abhängigkeiten müssen
begründet, exakt aufgelöst und mit Hashes gesperrt werden. Kein automatisches Baseline-Update
für Secret-Funde. False Positives nur einzeln nach Prüfung dokumentieren.
