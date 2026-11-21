# Wiedereröffnung und Episoden

Ein neues gültiges affected nach resolved/closed kann denselben Befund wieder öffnen.
Neue Episode, neuer offener Bearbeitungszeitraum, neue Policy-/Fristbewertung; die ursprüngliche
Finding-ID und first_detected_at bleiben erhalten. Alte Resolutionen, Abschlüsse, Ausnahmen
und Fristverletzungen bleiben historisch. Eine frühere Zuweisung wird nicht automatisch in
die neue Episode übertragen. Alte Ausnahmen gelten nicht für eine neue Episode.

Matching-Publikationen werden über den monotonen current_version-Zähler und die aktuellen
Input-Pointer geordnet. A→B→A kann eine neue gültige Publikation derselben Resultat-UUID sein.
Nur technische Änderungen begründen eine Wiedereröffnung eines scoped False-Positive-
Abschlusses: unveränderte Snapshot-/Regel-/Komponenten-/Affected-Semantik mit bloßen
CVSS-/Provenienzänderungen löst keine neue Episode aus. Risiko-Refreshjobs verändern
überhaupt keinen Lifecycle. Neue technische Basis erfordert erneute False-Positive-Prüfung.
