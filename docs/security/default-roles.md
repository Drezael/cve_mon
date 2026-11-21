# Standardrollen admin und user

Das Standarddeployment enthält die unveränderlichen Systemrollen `admin` und `user`.
Migration `00070_default_user_role` ergänzt `user` bei vorhandenen Installationen und
weist diese Rolle allen bestehenden Administratorkonten zusätzlich zu. Passwörter,
MFA-Einstellungen, Kontostatus, Server und Objektberechtigungen bleiben erhalten.
Die ergänzenden bisherigen Rollen `viewer`, `security_analyst` und `user_admin`
bleiben für bestehende Zuweisungen verfügbar.

`user` umfasst den normalen Betrieb mit eigenen Serverinventaren, das Lesen und
Bearbeiten berechtigter Findings sowie persönliche Mail-, Berichts- und
Spracheinstellungen. Die Rolle erteilt weder Benutzer-/Rollenverwaltung noch
instanzweite SMTP- oder Instanzeinstellungen. Globale Aktionsrechte ersetzen keine
Objektberechtigungen: fremde Server und Findings werden dadurch nicht sichtbar.
Die maßgeblichen Rechte stehen in `contracts/security/role-matrix.yaml` und im
laufzeitgleichen endlichen Berechtigungskatalog.

Über die Benutzerverwaltung neu angelegte Konten erhalten `user` automatisch. Sie
bleiben bis zur sicheren Aktivierung ohne voreingestelltes Passwort gesperrt. Eine
spätere explizite Rollenänderung kann einem normalen Konto weiterhin andere Rollen
oder keine Fachrolle zuweisen.

**Jedes Konto mit `admin` besitzt zugleich `user`.** Die API ergänzt die Basisrolle
bei der Rollenzuweisung und liefert die tatsächlich zugewiesenen Rollen zurück.
Ein Datenbanktrigger ergänzt sie auch beim Administrator-Bootstrap und bei direkten
Rollengrant-Vorgängen. Eine verzögerte Constraintprüfung verhindert das Entfernen
von `user`, solange `admin` vorhanden ist. Die Prüfung verwendet die bestehende
Sperre für Konto-/Rollenänderungen, damit parallele Transaktionen die Regel nicht
umgehen. Das Entfernen von `admin` bei verbleibendem `user` bleibt möglich, sofern
die Regel zum letzten nutzbaren Administrator erfüllt bleibt.

Der initiale Administrator wird weiterhin über den vorhandenen sicheren Bootstrap
angelegt und erhält beide Rollen. Es werden keine zusätzlichen Standardkonten oder
Standardpasswörter erzeugt. MFA bleibt optional und folgt der persönlichen
Kontokonfiguration. Die technische Ergänzung bestehender Rollenbindungen wird im
Audit mit dem auslösenden Dienst `role-defaults-service` protokolliert.

Die Benutzerübersicht zeigt die zugewiesenen Rollencodes je Konto in einer eigenen
Spalte. Mehrere Rollen erscheinen als einzelne Labels; Konten ohne Rollen werden
entsprechend gekennzeichnet. Die Benutzerlisten-API liefert hierfür das sortierte
Array `roles` bereits zusammen mit jeder sichtbaren Zeile. Die bestehenden
Berechtigungs- und Sichtbarkeitsfilter gelten auch für diese Rollenangaben.
