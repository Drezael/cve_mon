# Resolution und Aktualität

Die initiale versionierte Policy deaktiviert automatische Resolution und definiert keine
SLA oder willkürliche Altersgrenze. Ein Policy-Administrator kann nach frischer MFA eine
neue immutable Policy freigeben. automatic_resolution=true benötigt eine explizite maximale
Snapshot-Altersgrenze. Nur ein aktueller erfolgreicher Matching-Lauf mit not_affected,
complete-Qualität, global_negative=true, vollständig erfassten Bereichen und ohne betroffene,
unbekannte oder widersprüchliche Komponenten trägt automatische Resolution.

Serverstatus sowie Snapshot-, Enrichment- und Matching-Pointer werden beim Fachcommit mit
der engen DB-Funktion lock_current gesperrt und geprüft. Ein alter Worker darf nichts
Neueres überschreiben. Ein neues Kernelpaket, ein anderer Image-Tag, Paketabwesenheit in
Teilbeständen, eine Archivierung oder CVE-Rückzug sind keine Fixnachweise. Defaultmäßig
bleibt deshalb auch bei komponentenbezogenen Negativnachweisen aus Phase 17 der Befund offen.

Zeitpunkte sind verschieden: erste beobachtete Verarbeitung, Snapshot-Erfassung, tatsächliche
Matching-Erstellung und menschliche Entscheidung. Alle serverseitig in UTC; ein Beginn der
Verwundbarkeit wird nicht behauptet. is_stale und evidence_age_hours machen die Aktualität
sichtbar. Stale ist kein Lifecycle-Abschluss.

Auch die manuelle Schließung prüft die aktuelle Eingabebasis erneut. Ist eine maximale
Snapshot-Altersgrenze genehmigt, gilt diese zusätzlich für den manuellen Abschluss;
ein zuvor bestätigter Fehlalarm umgeht die Frischeprüfung nicht. Veraltete Evidenz bleibt
lesbar und kann zur Prüfung dokumentiert werden, berechtigt aber nicht zum Abschluss.
