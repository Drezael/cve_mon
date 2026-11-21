# RBAC-Prüfung Phase 23

Funktionsrecht und Objektbereich werden vor Lesen, Zählen und Mutieren geprüft. UUID-Kenntnis, Gruppenzugehörigkeit oder UI-Sichtbarkeit erzeugt keinen Grant. Admin-/ACL-Mutationen behalten Delegationsgrenzen, letzten nutzbaren Administrator, aktuelle Sitzung und frische Bestätigung. Berechtigungen werden nicht benutzerübergreifend gecacht.

Die Seitenoptimierung filtert den serverseitigen Objektbereich bereits in der materialisierten Seite. Detailprojektion und Zusammenfassungen sehen nur diese IDs; Verteilungsfilter sind ohne Inventarrecht weiterhin verboten. Die neue Lesesicht gewährt keine DML-/DDL-Rechte. Bestehende RBAC-/Objekt-/Konkurrenztests plus Dashboard-/Verwaltungsregression prüfen den Erhalt dieser Grenzen.
