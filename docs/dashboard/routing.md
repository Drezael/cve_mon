# Routing

BrowserRouter: /dashboard, /servers, /servers/:id, /groups, /groups/:id, /findings, /findings/:id, /notifications, /notifications/:id sowie /login und /mfa. Nicht authentifizierte Benutzer sehen die Anmeldung auf der aktuellen internen Adresse. Der Standard nach Anmeldung ist /dashboard bei security:overview:read, andernfalls /servers. Viewer erhalten keine zusätzlichen Rechte.

Nginx liefert index.html ausschließlich für bekannte Frontendpfade. /api/ und /internal/ fallen niemals auf HTML zurück. Bestehende exakte und geprüfte Fach-API-Routen behalten Vorrang. Unbekannte Pfade liefern 404. Queryparameter enthalten ausschließlich Filter und Pagination; keine Passwörter oder Sitzungstokens.
