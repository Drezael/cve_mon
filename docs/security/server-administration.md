# Schutz der Serververwaltung

Phase-8-Dashboardcookie, private Nginx-Gateprüfung, Origin/IP, vollständiger Principal aus
Phase 9. Keine vom Client behauptete Benutzerrolle. Maschinenbearer/mTLS sind kein Ersatz.
Die technische API-Domain verweigert Verwaltungszugriff. Kein Backend-Hostport.
Routerdependencies prüfen zuerst; Fachservice verifiziert Identität, Funktionsrecht, CSRF,
MFA und Reauth erneut in derselben DB-Transaktion wie fachliche Writes/Audit/Outbox.

Eigenes dashboard_admin-Poolcredential, kein SET ROLE. Resolver liest nur Credential-Version/
Widerruf und MFA-Aktivstatus; SELECT * auf Passwortcredentials und MFA-Methoden bleibt
verboten. Sessionpflege und Reauthverbrauch sind begrenzt freigegeben. Kein Konto-/Rollenwrite.
api_security behält seine bisherigen Rechte und erhält keine administrativen Inventory-Writes.

server:read benötigt explizite Server-ACL; deklarierter Plattformadmin-Lesezugriff aus Phase 9
bleibt erhalten. Serverlisten, Filter, Suche, Pagination und Gruppenzählungen wenden die ACL
in SQL an. 404 für verborgene Objekte, 403 bei fehlendem Funktionsrecht. Archivierte Server
sind nur dem Plattformadmin bei ausdrücklicher Anfrage zugänglich. Sichere Projektionen
enthalten nur administrative Metadaten, keine technischen Credentials/Benutzerkontakte.
