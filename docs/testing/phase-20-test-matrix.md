# Phase-20-Test- und Nachweismatrix

194 Kriterien aus T20.09.05. Die Zuordnung kombiniert Codeprüfung, native Tests,
Browsernachweise und bestehende fachliche Regressionen; sie behauptet keinen einzelnen
automatisierten Test je Kriterium. Alle Reportnamen beziehen sich auf `.runtime/test-reports`.

| Nr. | Kriterium | Nachweisgruppe | Referenz |
|---:|---|---|---|
| 1 | Bestehende Architektur verwendet. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 2 | Vorhandener Frontend-Stack geprüft. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 3 | Keine unnötige Frameworkmigration. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 4 | Statischer Produktivbuild. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 5 | Nginx als Frontend-Webserver. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 6 | Bestehender FastAPI-Dienst verwendet. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 7 | Keine zweite Fach-API. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 8 | Kein zusätzlicher Datenbankdienst. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 9 | PostgreSQL bleibt einzige fachliche Datenbank. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 10 | Kein Redis. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 11 | Kein zusätzlicher Broker. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 12 | Kein Docker-Socket. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 13 | Keine unnötigen Hostports. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 14 | Keine unnötigen Containerprivilegien. | Architektur, Deployment, 13 Dienste | docs/architecture/dashboard-architecture.md; phase-20-live-verification.json |
| 15 | HTTPS funktioniert. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 16 | Dashboard-Host korrekt. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 17 | API-Routing korrekt. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 18 | Same-Origin berücksichtigt. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 19 | Hostgebundene Cookies korrekt. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 20 | Forwarded-Header abgesichert. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 21 | Kein unsicheres CORS. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 22 | Keine internen APIs über Dashboard erreichbar. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 23 | Kein API-Fallback auf index.html. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 24 | HSTS-Strategie beibehalten. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 25 | CSP wirksam. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 26 | Caching sicher konfiguriert. | Nginx, TLS, Routing, CSP, Cache | scripts/dashboard/manage.py; tests/browser/dashboard.spec.ts; phase-20-infra-regression.xml |
| 27 | Login funktioniert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 28 | Ungültiger Login abgewiesen. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 29 | MFA funktioniert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 30 | MFA-Fehler behandelt. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 31 | Sessionprüfung funktioniert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 32 | Sessionablauf funktioniert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 33 | Logout funktioniert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 34 | Serverseitige Session invalidiert. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 35 | Client-Caches nach Logout bereinigt. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 36 | Browser-Back sicher. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 37 | Keine Tokens in Local Storage. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 38 | Keine Tokens in Session Storage. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 39 | Keine Tokens in URLs. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 40 | Keine zweite Authentifizierungsimplementierung. | Login, MFA, Session, Logout | src/auth.tsx; src/pages/Login.tsx; dashboard.spec.ts; phase-20-auth-regression.xml |
| 41 | RBAC aus Phase 9 integriert. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 42 | Objektberechtigung geprüft. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 43 | Server-ACL berücksichtigt. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 44 | Keine Rechte durch bloße Gruppenzugehörigkeit. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 45 | Berechtigungsabhängige Navigation. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 46 | Backendauthentifizierung bei jedem geschützten Abruf. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 47 | Keine fremden Serverdetails. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 48 | Keine fremden Findings. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 49 | Keine fremden Benachrichtigungen. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 50 | Keine fremden Aggregationswerte. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 51 | Kein IDOR. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 52 | Berechtigungsentzug wird berücksichtigt. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 53 | Keine ausschließlich clientseitige Sicherheitsprüfung. | Funktion und Objekt-ACL | cve_api/dashboard; tests/dashboard/test_native.py; phase-20-auth-regression.xml |
| 54 | Einheitliches Designsystem. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 55 | Header. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 56 | Sidebar. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 57 | Breadcrumbs. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 58 | Benutzermenü. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 59 | Responsive Navigation. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 60 | Dashboardroute. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 61 | Serverroute. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 62 | Gruppenroute. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 63 | Findingroute. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 64 | Notificationroute. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 65 | Deep Links. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 66 | Browsernavigation. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 67 | 403-Seite. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 68 | 404-Seite. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 69 | Keine funktionslosen Phase-21-Buttons. | Navigation und Layout | src/main.tsx; src/style.css; Browser-Screenshots; axe |
| 70 | Servergesamtzahl im berechtigten Scope. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 71 | Offene Findings korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 72 | Bestätigte Betroffenheit korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 73 | Mögliche Betroffenheit korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 74 | Unknown getrennt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 75 | Kritische Findings korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 76 | Hohe Priorität korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 77 | KEV-relevante Findings korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 78 | Überfällige Findings korrekt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 79 | Keine Paketdoppelzählung. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 80 | Keine Serverdoppelzählung. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 81 | Keine falschen Nullwerte bei API-Fehlern. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 82 | Datenstand angezeigt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 83 | Berechtigungsumfang berücksichtigt. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 84 | Keine globale Kennzahl für unberechtigte Server. | KPI und Inventarqualität | dashboard/service.py; test_scoped_dashboard_and_source_context; partial_inventory |
| 85 | Prioritätsverteilung korrekt. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 86 | Lifecycle-Verteilung korrekt. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 87 | Betroffenheitsverteilung korrekt. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 88 | Zeitliche Entwicklung korrekt. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 89 | Erkennung und Behebung unterschieden. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 90 | Reopening berücksichtigt. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 91 | Keine künstlichen Live-Daten. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 92 | Zugängliche Datenalternative. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 93 | Keine irreführende Skalierung. | Verteilungen und UTC-Ereignisse | src/pages/Overview.tsx; dashboard/service.py; Vitest und native Trends |
| 94 | CVSS-Version angegeben. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 95 | KEV separat. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 96 | EPSS separat. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 97 | EPSS-Prozentwert korrekt. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 98 | EPSS-Datenstand berücksichtigt. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 99 | Fehlende EPSS-Daten nicht als 0. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 100 | Keine Betroffenheit allein durch hohen CVSS. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 101 | Keine Betroffenheit allein durch KEV. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 102 | Keine Betroffenheit allein durch EPSS. | CVSS, KEV, EPSS | FindingRows; Facts; Contract risk values; Phase-18-Domainregression |
| 103 | Serverliste vorhanden. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 104 | Serversuche funktioniert. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 105 | Serverfilter funktionieren. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 106 | Pagination funktioniert. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 107 | Serverdetails funktionieren. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 108 | Gruppenübersicht vorhanden. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 109 | Mehrfachmitgliedschaften korrekt. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 110 | Primärgruppe korrekt. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 111 | Gespeicherte Gruppenreihenfolge korrekt. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 112 | Gespeicherte Serverreihenfolge korrekt. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 113 | Archivstatus korrekt. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 114 | Keine Gruppenänderung. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 115 | Keine Primärgruppenänderung. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 116 | Keine Sortieränderung. | Server, Gruppen und Reihenfolge | src/pages/Servers.tsx; test_group_orders_deduplication_and_missing_inventory; Auth-Regression |
| 117 | Snapshot-ID vorhanden, soweit berechtigt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 118 | Erfassungszeit korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 119 | Betriebssystem korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 120 | Distribution korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 121 | Release korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 122 | Paketanzahl korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 123 | Kernelinformation korrekt. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 124 | Dockerinformationen korrekt, soweit vorhanden. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 125 | Datenvollständigkeit sichtbar. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 126 | Fehlende Inventare sichtbar. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 127 | Veraltete Inventare sichtbar. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 128 | Matching-Aktualität sichtbar. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 129 | Keine falsche Entwarnung durch fehlende Daten. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 130 | Kein Inventarupload in Phase 20. | Inventar, Aktualität und Vollständigkeit | 00028_dashboard_reads.py; partial_inventory; src/pages/Servers.tsx |
| 131 | Finding-Liste vorhanden. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 132 | Suche funktioniert. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 133 | Filter funktionieren. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 134 | Sortierung funktioniert. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 135 | Pagination funktioniert. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 136 | Finding-Details vorhanden. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 137 | Technische Betroffenheit sichtbar. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 138 | Bearbeitungsstatus separat. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 139 | Risikoakzeptanz separat. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 140 | CVE-ID korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 141 | Serverreferenz korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 142 | Matching-Result-ID korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 143 | Enrichment-Revision korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 144 | Betroffene Komponenten sichtbar. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 145 | Installierte Versionen korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 146 | Fixversionen nur bei Evidenz. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 147 | Quellenprovenienz sichtbar. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 148 | Entscheidungsgrund sichtbar. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 149 | Finding-Historie vorhanden. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 150 | Episoden korrekt. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 151 | Keine Finding-Veränderung. | Finding, Evidenz und Historie | src/pages/Findings.tsx; dashboard/context; tests/findings; Domain-Regression |
| 152 | Berechtigte Benachrichtigungsliste vorhanden. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 153 | Versandstatus korrekt. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 154 | Postfix-Annahme nicht mit Zustellung verwechselt. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 155 | Unklarer Zustellstatus korrekt. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 156 | Unterdrückung korrekt. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 157 | Keine fremden Empfängerinformationen. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 158 | Keine freie SMTP-Funktion. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 159 | Keine direkte n8n-Steuerung. | Benachrichtigungen und Zustellsemantik | src/pages/Notifications.tsx; tests/notifications; Domain-Regression |
| 160 | Keine XSS-Lücke. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 161 | Kein Mass Assignment. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 162 | Kein Open Redirect. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 163 | Kein unberechtigter Datenabruf. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 164 | Keine sensiblen URLs. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 165 | Keine Secrets im Frontend-Build. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 166 | Keine externen unsicheren Skripte. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 167 | CSP getestet. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 168 | Cache-Leak-Tests erfolgreich. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 169 | Logout-Tests erfolgreich. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 170 | Sessionablauf-Tests erfolgreich. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 171 | Keine direkte PostgreSQL-Verbindung. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 172 | Keine direkte Worker-Verbindung. | Sicherheitsgrenzen | api.ts; auth.tsx; security.test.tsx; CSP-/Logout-/MFA-Browsertests |
| 173 | TypeScript-Prüfung erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 174 | Frontend-Linting erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 175 | Build erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 176 | Komponententests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 177 | API-Integrationstests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 178 | Browser-E2E-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 179 | Authentifizierungstests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 180 | RBAC-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 181 | Kennzahlentests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 182 | Diagrammtests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 183 | Server- und Gruppentests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 184 | Finding-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 185 | Notification-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 186 | Sicherheitstests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 187 | Responsive-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 188 | Accessibility-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 189 | Performance-Baseline dokumentiert. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 190 | Nginx-Tests erfolgreich. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 191 | Keine kritischen bekannten Sicherheitsfehler. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 192 | Dokumentation vollständig. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 193 | Übergabe an Phase 21 vorbereitet. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
| 194 | Keine unzulässigen Architekturänderungen. | Qualität, Betrieb und Übergabe | phase-20-check.log; phase-20-dashboard-check.log; phase-20-*.xml; Dokumentation |
