# Autorisierung in cve-api 0.9.0

Anmeldung bleibt Phase 8. Ein Principal ist unveränderlich und enthält Benutzer-/Session-
UUID, aktiven Zustand, vollständiges Authniveau, MFA, auth_version, verifizierte Rollen und
menschliche Berechtigungen. Er entsteht ausschließlich aus AuthService.resolve und einer
PostgreSQL-Rollenabfrage. Keine Header-/Bodyrollen, JWT-Abkürzung oder Bearer-Maschinenidentität.

Default Deny: bekannter Katalogeintrag + explizites Rollenrecht + ausreichende MFA + ggf.
Server-ACL. Gruppen/Primärgruppen verleihen keine Rechte. Eine ausdrückliche Plattform-
Adminentscheidung deckt Serverlesezugriff, aber Dashboard-Upload braucht auch für Admin
seinen gesonderten ACL-Scope. Unbekannte Aktionen und Legacy-/Maschinenrechte werden nie
als Browserrechte akzeptiert. Zusätzliche Rollen erhalten nur nichtadministrative delegierbare
Rechte. Admin/user_admin benötigen MFA aus derselben Phase-8-Authentifizierung.

Routerdependencies prüfen zuerst; jeder öffentliche fachliche Administration-Serviceaufruf
prüft dieselbe Cookieidentität/Berechtigung nochmals in seiner Transaktion. Kein vom Aufrufer
vorgegebener User-ID-/Principal-Ersatz. Spätere Fachservices verwenden load_principal und
decide im selben kontrollierten SQL-Kontext oder die vollständig prüfenden Wrapper.
Niedrige SQL-/Policyhelper erwarten diesen verifizierten transaktionslokalen Kontext;
ein langlebig gespeicherter Principal ist keine neue Autorisierungsquelle.

Globaler Advisory-Lock 909001: normale Autorisierungslesevorgänge shared, Mutationen und
bestehende Auth-Kontovorgänge exclusive, jeweils vor Benutzer-/Session-/Objektlocks.
So kann ein vor Commit positiv geprüfter Request fertiglaufen; neue Requests nach einem
Widerruf prüfen die neue Revision bzw. erhalten 401 wegen widerrufener Session. Keine
Berechtigungscaches. Native Deferrable-Constraints schützen zusätzlich den letzten Admin.
Standard statement_timeout und begrenzte Pools bleiben aktiv. Rohe Operator-SQL-Änderungen
können bei konkurrierendem Zugriff einen Transaktionsretry benötigen, ohne unsicher zu committen.

Audit und authorization.security-Outbox teilen die Mutationstransaktion. Actor und Ziel
sind getrennt; feste Aktionsnamen, UUIDs, Ergebnis, Korrelation, keine Credentials. Begrenzte
Denied-Protokolle werden nach Rollback separat gespeichert (maximal zehn pro Akteur/Minute).
Kein RLS-Versprechen pro menschlichem Benutzer: api_security ist ein begrenzter vertrauenswürdiger
Backendkontext. Rollen-RLS schützt Systemrollen; native Dienstrechte und Serviceprüfungen ergänzen sich.

Der geschützte Auditdatensatz speichert zusätzlich Rollen-/Permission-IDs, ACL-Grants und
Revisionen; Profiländerungen nur Feldnamen und einen Grund-Digest, keine Kontaktwerte.
Outbox trägt die Audit-ID und einen Änderungsdigest, keine vollständigen Verwaltungsdaten.
Metadaten maximal 32 KiB, keine Credentials. Legacy-ACL-Sets über 100 Einträge werden
mit 409 zur kontrollierten Operatorprüfung zurückgewiesen, niemals still abgeschnitten.

Geschütztes Auditmetadata beschreibt die Änderung mit Rollen-/Server-/Benutzer-UUIDs,
endlichen Permissions und Revisionen; Gründe werden bei normalen Änderungen nur als Digest
aufgenommen, Profilwerte nicht kopiert. Outbox enthält Audit-ID und Änderungsdigest statt
der vollständigen Metadaten. Auditmetadata ist auf 32 KiB begrenzt. ACL-Sets über 100
Altbestandseinträgen werden mit 409 zur Operatorprüfung abgewiesen, niemals still gekürzt.
