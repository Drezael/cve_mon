# Auswirkungen von Phase 0 auf Phase 1

Stand: 05.11.2026. **Status: completed. Abweichungen korrigiert und erneut lokal abgenommen.**

| Bereich / betroffene Phase-1-Aufgaben | Vorher | Korrektur und Nachweis |
|---|---|---|
| Struktur / T01.01.02 | Bereichsverzeichnisse ohne konkrete Verträge | docs/api, ADRs, Beispielverzeichnis und Pflichtmanifest ergänzt; vorhandene Struktur erhalten |
| Datenhoheit / T01.01.02–04 | Upload-/Admin-Verzeichnisse konnten als zusätzliche Dienste missverstanden werden | cve-api-Annahmekontexte, cve-inventory-Verarbeitung und API-Administration konkret verknüpft; Dashboard ohne direkte DB-Rolle |
| Datenbank / T01.01.04 | PostgreSQL als einziges System ohne ausgearbeitetes Modell | Zwei logische Datenbanken im selben PostgreSQL-System, acht Fachschemas, explizite Inventar-/Admin-Rollentrennung |
| Architekturhinweise / T01.01.04, T01.05.03 | Phase-0-Ergebnisse fehlten | README, Bereichsindizes und Entwicklungsdokumentation auf tatsächliche Verträge umgestellt |
| Abhängigkeiten / T01.02.03–04 | Kein OpenAPI-Validator; RFC3339-Formatplugin nicht explizit installiert | Zwei direkte Development-Abhängigkeiten ergänzt, transitive Versionen/Hashes aufgelöst und frisch installiert |
| JSON-Verträge / T01.04.02–03 | Nur JSON-Syntax und Schema-Definitionen | Striktes JSON ohne doppelte Keys/NaN; aktive UUID-/Zeitprüfung; sechs explizite Beispielerwartungen inklusive Ablehnungsgrund |
| OpenAPI / T01.04.03 | YAML-Syntax ohne API-Semantik | OpenAPI 3.1 semantisch, lokale Ref-Auflösung; Remote-/Pfadflucht-Refs verboten |
| Sicherheitsgrenzen / T01.04.02–04 | Allgemeines Secret-Scanning | Zusätzlich UND-Auth, Scopes, Admin-/Statusgrenzen, Dienste/Netze/DB-Hoheit als Vertragsregressionen geprüft; Baseline unverändert |
| Make/CI / T01.04.05, T01.05.01–02 | make validate ohne konkrete Phase-0-Artefakte | Bestehender Target/Workflow unverändert aufrufbar, Validator führt Vertrags-/Dokumentprüfungen automatisch aus und reicht Fehler weiter |
| Abnahme / T01.05.03–05 | 51 Tests, Phase-0-Verträge als offene Voraussetzung | 117 Tests, 19 zusätzliche Abnahmeschritte, Status/Übergabe/Phase-1-Abnahme aktualisiert |

## Geänderte Phase-1-Artefakte

README-/Dokumentationsanpassungen, requirements/dev.in und dev.txt sowie
scripts/validate_repository.py. Ergänzt wurden scripts/validate_contracts.py,
tests/unit/test_contracts.py und das Vertragsmanifest.
Keine Änderung an .env.example, .gitignore, Ruff-/Mypy-/Pytest-Grundregeln,
Make-Targetnamen, CI-Action-Pins oder Secret-Ausnahmen erforderlich.
Mypy bleibt strikt, YAML-Lintregeln wurden nicht gelockert.

## Nachweise

117 Tests bestanden; 66 neue Fälle prüfen unter anderem verschachtelte Steuerfelder,
Zeit-/UUID-Formate, Teilinventare, falsche Ablehnungsgründe, Auth-Oder-Verknüpfung,
Admin-/Statusrechte, externe Referenzen, unerlaubten Egress und administrative Inventory-Rollen.
Die frische Installation verwendet den aktualisierten Hash-Lock. Erneutes Setup erhält
Interpreter und lokale Markierung. Ein defekter positiver Inventarfall, ein OpenAPI-Semantikfehler
und mTLS ODER Token erzeugen jetzt nachweislich Fehlerstatus in make validate.

| Prüfung | Exit-Code | Ergebnis |
|---|---|---|
| Frisches Git-Repository | 0 | Erfolgreich |
| Neue .venv mit Hash-Installation | 0 | Erfolgreich |
| Wiederholtes Setup mit erhaltenem Interpreter/Marker | 0 | Erfolgreich |
| make help | 0 | Erfolgreich |
| make format | 0 | Erfolgreich |
| make check in frischer Umgebung | 0 | Erfolgreich |
| pip check | 0 | Erfolgreich |
| Fehlende pyproject.toml erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültiges YAML erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültiges JSON erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültige Schema-Definition erkannt | 2 | Erwartet fehlgeschlagen |
| Lintfehler stoppt make check | 2 | Erwartet fehlgeschlagen |
| Fehlschlagender Pytest stoppt make check | 2 | Erwartet fehlgeschlagen |
| Neues synthetisches Secret stoppt make check | 2 | Erwartet fehlgeschlagen |
| Vollständiger Check nach Bereinigung | 0 | Erfolgreich |
| mTLS ODER Token statt UND wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Semantisch ungültige OpenAPI wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Beschädigtes positives Inventarbeispiel wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Verträge nach Bereinigung gültig | 0 | Erfolgreich |


## Noch offene Voraussetzungen

Die Phase-0-Verträge und das Datenmodell fehlen nicht mehr. Weiter offen: separate Originale
Gesamtkonzept 3.12/Entwicklungsplan 1.2, konkretes Phase-2-Konzept, gehostete GitHub-CI
und die in OP00.01–11 benannten zukünftigen Runtime-Nachweise. Diese werden nicht als
bereits ausgeführt behauptet. Phase 1 bleibt lokal abgeschlossen, Phase 2 wurde nicht begonnen.
