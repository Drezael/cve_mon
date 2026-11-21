# Letzten nutzbaren Administrator schützen

Nutzbar: aktiver Benutzer, admin-Systemrolle, existierende nicht widerrufene Credentials,
aktivierte nicht widerrufene runtime_version=1-MFA. user_admin zählt nicht. Die Datenbank
prüft den persistenten zulässigen Faktorstatus; tatsächlicher Schlüssel-/Faktorbesitz und
Backups bleiben Betreiberverantwortung.

Native deferrable Constraint-Trigger auf Benutzerstatus, Adminrollenzuordnung, Credentials
und MFA betrachten den finalen Transaktionszustand unter Advisory-Lock und geschütztem
administration_state. Nach dem ersten nutzbaren Admin ist die Invariante armed und darf
keinen gewöhnlichen Commit mit null zulassen. Temporäres Löschen/Einfügen derselben Rolle
innerhalb einer Transaktion ist zulässig. API erzwingt Constraints vor Erfolgsausgabe;
Konflikte sind 409, die komplette Änderung samt Sessionwiderruf rollt zurück.

Vor dem ersten bestätigten Bootstrap-MFA kann null vorliegen. Es gibt dann keine vollständige
Adminsession zum Aufruf einer Verwaltungsoperation. Runtime kann den armed-Zustand weder
lesen noch ändern; nur ein sicherer Aggregatstatus ist vorgesehen. Kein öffentlicher oder
automatisch angelegter Notfalladmin. Regulärer erster Bootstrap bleibt einmalig.

Auch Phase-8-Selbstrecovery/Faktorenwechsel dürfen den letzten Admin nicht unbrauchbar machen.
Dafür muss vorher ein weiterer nutzbarer Admin eingerichtet sein oder ein kontrollierter
Offline-Operatorplan gelten. Konkurrenztests: zwei parallele Selbstdeaktivierungen bzw.
Rollenentzüge → ein Erfolg, eine Ablehnung, mindestens ein nutzbarer Admin bleibt.
