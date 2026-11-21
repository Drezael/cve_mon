# Rollenmodell

Verbindlich: permission-catalog.yaml und role-matrix.yaml unter contracts/security.
38 endliche menschliche Rechte; inventory:submit bleibt separat maschinell. Bestehende
Legacy-Rechte werden erhalten, aber nicht in der Browserengine freigegeben.

admin besitzt ausdrücklich die Katalogrechte, mit MFA/Reauth, Zielregeln, eigenem Upload-ACL
und Letzter-Admin-Invariant. Kein generischer Wildcard-Bypass. user_admin verwaltet nur
nicht privilegierte Ziele und vergibt nur viewer/security_analyst. Keine eigenen/Admin-/
User-Admin-Konten bearbeiten, keine privilegierten Rollen, Rollen-CRUD oder MFA-Recovery.
Analyst und Viewer benötigen konkrete Serverfreigaben; Analyst hat keine Standard-Uploads
und keine standardmäßige Finding-Bearbeitung. Mehrere Rollen vereinigen explizite Rechte.

Zusätzliche Rollen: nur Admin, eindeutiger Code/normalisierter Name, bekannte delegierbare
menschliche Rechte. Keine Benutzer-/Gruppen-/Sortierverwaltung oder inventory:submit.
Systemrollen nicht über gewöhnliche API veränderbar. Revisionen sind optimistisch;
Änderung/Löschung einer zugewiesenen Rolle widerruft betroffene Sessions. Rollenentzug und
Rollenersatz erhöhen User-auth_version. Selbstzuweisung neuer Rollen wird immer abgelehnt;
Selbstentzug ist bei erhaltener nutzbarer Administration zulässig.

Das vorbereitete audit:read ist für user_admin auf eigene Verwaltungsaktionen beschränkt;
ein allgemeiner Audit-Leseendpunkt ist in Phase 9 nicht veröffentlicht. Spätere Audit-Reader
müssen Actor-/Zielgrenzen zusätzlich zur Permission durchsetzen.
