# RBAC-Grenzen

[Architektur](../architecture/authorization.md), [Rollen](../architecture/role-model.md).
Positive Entscheidung je Funktion und Objekt; kein Default Allow. catalog/ad hoc Rollennamen
verleihen keine ähnlichen Rechte. Endliche neue Rechte werden per versionierter Migration
zugeordnet. Eine Erweiterung des Pythonkatalogs allein vergibt keine neuen DB-Rollenrechte.
System-Seeds werden vom Betreiberwerkzeug exakt gegen die Matrix geprüft.

Menschliche Rollen sind keine PostgreSQL-Rollen und verleihen keine technischen Upload-
Tokenrechte. Allgemeine Dienste erhalten keine Superuser/BYPASSRLS- oder Gruppenwrites.
Der API-Reader bleibt separat; kontrollierte Security-Operationen verwenden api_security.
Zusätzliche Rollen sind auch nativ gegen nicht delegierbare Permission-Zuordnung geschützt.
