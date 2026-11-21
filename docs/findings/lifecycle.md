# Lifecycle findings-1

Technische Betroffenheit, Lifecycle (open/in_progress/resolved/closed) und review_state sind
getrennte Dimensionen. Risikoakzeptanz ist eine befristete Ausnahme und kein technischer Fix.
Affected kann ein neues Finding eröffnen; ein wiederholter gültiger Nachweis erhält Bearbeitung
und Finding-ID. Unknown, potentially_affected, not_applicable, fehlende Daten oder Datenalter
schließen keinen offenen Befund. Zurückgezogene CVEs erzeugen Prüfbedarf, keine Patchbehauptung.

Open → in_progress benötigt eine autorisierte Triage. Open/in_progress → resolved benötigt
eine freigegebene Fixrichtlinie und vollständigen aktuellen Beleg. Closed benötigt zusätzlich
eine manuelle Abschlussaktion; alternativ einen bestätigten False Positive auf genau dieser
Eingabebasis. Eine neue bestätigte technische Betroffenheit eröffnet eine neue Episode.
Risikoänderungen allein eröffnen keine Episode. Episodenöffnungen und -abschlüsse bleiben
append-only erhalten; alte Fristen und Behebungen werden nicht überschrieben.
