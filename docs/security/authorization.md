# Autorisierung T00.05.06

Aktuelle Deployment-Ergänzung: [Standardrollen admin und user](default-roles.md).

Default Deny. Eine gültige Identität allein berechtigt zu keiner Fachoperation.
Jede OpenAPI-Operation nennt x-permission und x-object-scope. Serverseitig zuerst aktuellen
Konto-/Sitzungszustand, dann Berechtigung, dann alle betroffenen Objekte prüfen.

| Rolle | Berechtigungen / Objektbereich |
|---|---|
| Administrator (Systemrolle) | Alle dokumentierten Plattformrechte einschließlich servers/groups/users/roles/tokens:manage, deployment:status:read; globale Verwaltung, MFA zwingend |
| Security Analyst | cve:read, inventory:read, inventory:upload:dashboard, matching:read, findings:read/write, reports:read/create, metrics:read; ausschließlich zugewiesene Server/Gruppen |
| Benutzeradministrator | users:manage, roles:manage, tokens:manage, audit:read; delegierbare Rechte und MFA-/Letzter-Admin-Regeln zusätzlich prüfen |
| Viewer | cve:read, inventory:read, matching:read, findings:read, reports:read, metrics:read; ausschließlich zugewiesene Server/Gruppen |
| Technischer Principal | Nur inventory:submit und explizite principal_server_access-IDs; kein Benutzerkonto |
| Interner Dienst | Feste aufrufende Dienst-/Methoden-Allowlist und gegebenenfalls delegierter menschlicher Actor; keine globale Adminrolle |

session:self ist ausschließlich implizites Recht einer vollständig gültigen eigenen Sitzung,
keine zuweisbare administrative Rolle. Administrator-Systemrolle und Basisberechtigungen sind
geschützt. Benutzerdefinierte Rollen dürfen nur bekannte, durch den Vergeber delegierbare Rechte
erhalten, niemals eigene privilegierte Scopes erfinden. Keine Selbstprivilegierung. Administrative :manage-Rechte erfordern unabhängig vom
Rollennamen bestätigte MFA; sensible Admin-Writes zusätzlich frische starke Bestätigung.

Lesender Objektzugriff ist Union expliziter user_server_access und aktiver Mitgliedschaften aus
user_group_access; zusätzlich muss die globale Aktionsberechtigung vorhanden sein.
Dashboard-Upload verlangt zusätzlich ein direktes can_upload-Serverrecht; Gruppenzugriff erweitert keine Upload-Allowlist.
Keine implizite Verwaltung durch Gruppenzugriff. groups:manage/servers:manage sind administrative
Rechte mit explizitem globalem oder später versioniert eingeschränktem Scope; v1-Verwaltung ist global.
Änderungen an Gruppen wirken sofort auf zukünftige Autorisierungsentscheidungen, ohne dass
Inventare Gruppen oder Benutzergrants selbst verändern. Berechtigungscaches benötigen auth-/scope-
Version und dürfen entzogene Rechte nicht bis Sitzungsende weiterlaufen lassen.

Listen, Counts, Exporte und Reportdownloads prüfen denselben aktuellen Objektbereich.
Fremde/unsichtbare Objekt-ID: 404 statt Existenzoffenlegung; fehlender Aktionsscope: 403.
Änderungen über mehrere Server/Gruppen werden vollständig oder gar nicht ausgeführt.
Niemals Autorisierung nur im Browser oder anhand übermittelter owner-/group-Felder.

Letzter aktiver Administrator, Sessionwiderruf und Rechteänderungen sind atomar geschützt
(siehe security.md). Technische Upload-Tokens und n8n dürfen weder Server registrieren noch
Gruppen/Primärgruppen/Sortierung verändern. Inventory Processor und Matcher haben auch auf
Datenbankebene keine entsprechenden Schreibrechte.
