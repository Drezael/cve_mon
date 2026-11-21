# Eskalation und Datenlecks verhindern

| Angriff | Grenze und Nachweis |
|---|---|
| gefälschte User-/Rollenheader | Phase-8-Gateway plus DB-Session; echte HTTPS-/Backendtests |
| Mass Assignment | extra=forbid, keine Rollen/Status/Hash/MFA/Profile-Schreibfelder |
| User Admin übernimmt Admin | geschützte Ziele unsichtbar, nur Standardrollen, kein Recovery-Recht |
| eigene Rolle/ACL erhöhen | neue eigene Rollenzuordnung und eigene ACL-Grants abgelehnt |
| zusätzliche Rolle wird Gruppenadmin | Python-Allowlist und nativer nondelegable-Trigger |
| BOLA / fremde Server-ID | bekannte Funktion 403, nicht sichtbares Objekt 404; SQLfilter vor Pagination |
| Gruppen-/Primärgruppenwechsel | keinerlei Browser-ACL-Vererbung, gefilterte Zählungen |
| altes Recht nach Widerruf | frische Daten pro Serviceaufruf, Userauthversion und Sessionwiderruf |
| parallele letzte Admins verlieren Zugriff | Advisory-Serialisierung und deferred native Invarianten |
| MFA-Recovery übernimmt Konto | frischer anderer Admin, private unabhängige Übergabe, Passwortkontext/neues Enrollment |
| technische Tokens an Adminroute | ausschließlich Sessioncookie, keine Token-/JWT-Abkürzung |
| DB-Ausfall | 503, keine positive Fallbackentscheidung |

Operatoren mit Migrations-/Host-/Schlüsselhoheit bleiben vertrauenswürdig. Keine Behauptung
vollständiger Phishing-/XSS-Abwehr; die Phase-8-Grenzen gelten weiterhin. Bei korrektem
Role-Read darf ein bereits vor einem Widerruf autorisierter Request noch abschließen;
die Mutation wartet auf dessen Transaktion. Kein wiederverwendbarer Principalcache.
