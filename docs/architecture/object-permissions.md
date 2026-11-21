# Explizite Objektberechtigungen

Die bestehende user_server_access-Tabelle bleibt die einzige Browser-Server-ACL-Datenhaltung.
Ergänzt sind UUID, Zeit/Erteiler/Revision und Findings-Flags. Sichtbar view=can_read;
inventory_upload=can_upload; findings_read/findings_manage gesondert. Upload/Findings
benötigen view, findings_manage außerdem findings_read. Eine zusätzliche kleine Tabelle
server_acl_versions hält die Revision einer gesamten ACL-Ersetzung, auch wenn sie leer ist.

Administration.servers/groups/check_object verifizieren erneut die vollständige Session.
SQL-EXISTS filtert bereits vor Suche, Sortierung, Pagination und Aggregation. Kein Laden
aller Server mit anschließendem Frontendfilter. Gruppen zählen nur sichtbare Server;
leere unsichtbare Gruppen werden nicht geliefert. Primärgruppe und Mehrfachmitgliedschaft
sind keine Freigaben. Die frühere effective_server_access-View ist für Browser ungeeignet;
keine neue Phase-10-/11-Fachfunktion darf diese als Ersatz der Engine benutzen.

Adminplattform-Lesen ist explizit erlaubt; für Dashboard-Uploads gilt kein solcher Bypass.
ACL-Verwaltung nur Admin mit frischem Einmal-Reauth, Server-/Benutzer-UUID und Gesamtversion.
Keine Selbsteinträge im erteilten ACL-Set; Rechte für eigene Uploads muss ein anderer Admin
verantworten. ACL-Änderungen widerrufen die Sessions aller betroffenen Grantees und erhöhen
Autorisierungsversionen. Die eigentliche Server-/Gruppen-/Upload-API folgt in Phase 10/11.
