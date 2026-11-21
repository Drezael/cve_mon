# Triage und Zuständigkeit

Die API übernimmt nur explizite typisierte Felder. Jede Mutation benötigt CSRF, eine
If-Match-Version und eine sinnvolle Begründung. Der Akteur stammt aus der verifizierten
Sitzung; actor_user_id, technische Statuswerte, Gruppen oder Fristen können nicht frei
übermittelt werden. Die Datenbank revalidiert Session, Benutzerstatus, Funktionsrechte,
Objektrechte und bei privilegierten Aktionen frische MFA. Notizen sind Plaintextdaten.

start, confirm, needs_review, suspect_false_positive und fix_check sind explizite Aktionen.
Fix_check plant eine erneute Prüfung, keine frei behauptete Resolution. Reviews referenzieren
die konkrete Matching-Revision; confirmed_false_positive braucht ein zusätzliches Recht und
frische MFA. Kompensierende Maßnahmen speichern Beschreibung, Scope, Nachweis und optionales
Ablaufdatum; sie ändern nicht die technische Betroffenheit.

Zuständigkeit verweist auf vorhandene aktive Benutzer mit finding:update und aktuellen
Serverrechten. Keine neue Benutzerverwaltung, keine Besitzervermutung aus Gruppennamen.
Deaktivierte oder nicht mehr berechtigte Bearbeiter bleiben historisch sichtbar;
assignee_is_eligible zeigt die aktuelle Verwendbarkeit. Jede Änderung wird protokolliert.
