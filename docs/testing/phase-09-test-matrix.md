# Phase-9-Testmatrix

| Bereich | Praktischer Nachweis |
|---|---|
| Katalog/Matrix | endliche 38 menschliche Rechte, vier exakte Rollen, kein Maschinenrecht/Wildcard |
| Eingaben | zusätzliche Felder/MFA/Status/Rollen/Hashes verweigert; Versionen und Delegierbarkeit |
| Benutzer | create/pending, manuelle Einmalaktivierung, Listen/Suche/Pagination, PATCH/Lebenszyklus/Archiv |
| Rollen | User-Admin-Ziel-/Standardrollenlimit, eigene Erhöhung verweigert, Revisionen/Systemrollen geschützt |
| Session/CSRF | keine/falsche/alte Identität, frische einmalige Reauth; Widerruf nach Konto/Rolle/ACL |
| ACL/BOLA | explizite Server-UUID, zwei Uploadbedingungen, verdeckte Objekte/Suche/Pagination/Aggregate |
| Gruppen | Mehrfachmitgliedschaft und Primärgruppe ändern nicht ACL; unsichtbare Gruppenzählungen fehlen |
| Letzter Admin | native Credential-/MFA-Widerrufe; Status/Roleentzug; zwei parallele Admins, genau einer bleibt |
| Recovery | anderer starker Admin + unabhängiger privater Handoff; keine Geheimnisse in Adminantworten |
| HTTPS/Docker | reales Nginx/API/PG; Admin/User-Admin/Viewer, Proxy-/Maschinentoken, Restart/DB-Ausfall |
| Performance | 1000 Benutzer, 200 Rollen, 4000 Server, 500 Grants, 24 parallele gefilterte Seiten; Indexplan/konstante Queryanzahl |
| Regression | Standard, Auth/MFA, DB, Nginx, API, Envoy, Postfix, Jobs/Outbox vollständig |

make authorization-test / authorization-integration / authorization-security /
authorization-concurrency, CVE_DOCKER_SUDO=1 bei Docker. Tests verwenden ausschließlich
eigene UUID-Projekte und Phase-8-Test-PKI/Credentials. Fixture-Owner darf Testreauth und
einen isolierten Invariant-Bootstrap vorbereiten; Runtime kann dies nicht. Echte Reauth/TOTP
wird zusätzlich in der übernommenen Authsuite geprüft. Keine produktiven Benutzer/ACLs
oder fremden Container werden verändert, keine externen Nachrichten.
