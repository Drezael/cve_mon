# Phase-22-Testmatrix

177 Pflichtkriterien aus T22.09.05. Codeprüfung und automatisierte Nachweise werden gemeinsam zugeordnet; es wird kein separater automatischer Fall je Kriterium behauptet. Berichte: .runtime/test-reports/phase-22-*.

| Nr. | Kriterium | Nachweis |
|---:|---|---|
| 1 | Bestehende Architektur berücksichtigt. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 2 | Python 3.12. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 3 | Vorhandener FastAPI-Dienst. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 4 | PostgreSQL als Datenhaltung. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 5 | Vorhandene Jobinfrastruktur. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 6 | Kein Redis. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 7 | Kein zusätzlicher Broker. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 8 | Kein zusätzlicher Monitoringdatenbankdienst. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 9 | Kein Docker-Socket. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 10 | Keine unnötigen privilegierten Container. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 11 | Keine unnötigen öffentlichen Ports. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 12 | Keine unkontrollierte Egress-Verbindung. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 13 | Tatsächlich vorhandene Dienste registriert. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 14 | Stabile Service-IDs. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 15 | Versionierte Prüfdefinitionen. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 16 | Kritikalität berücksichtigt. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 17 | Dienstabhängigkeiten vorhanden. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 18 | Keine Abhängigkeitszyklen. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 19 | Erwartete Aktivität berücksichtigt. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 20 | Keine erfundenen Dienste. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 21 | Liveness. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 22 | Readiness. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 23 | Functional Health. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 24 | Dependency Health. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 25 | Backlog Health. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 26 | Data Freshness. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 27 | Monitoring Freshness. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 28 | Timeouts. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 29 | TLS-Validierung. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 30 | Fehlerklassifikation. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 31 | Schema-Validierung. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 32 | Keine freien Prüfziele. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 33 | Kein SSRF. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 34 | Keine ungeplanten Schreiboperationen. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 35 | Nginx geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 36 | FastAPI geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 37 | PostgreSQL geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 38 | Envoy geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 39 | Postfix geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 40 | n8n geprüft. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 41 | Keine Envoy-Admin-Freigabe. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 42 | Keine Postfix-Queue-Manipulation. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 43 | Keine n8n-Workflowmanipulation. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 44 | Kein SMTP-Testversand. | catalog.py, models.py, probes.py und feste lokale Adapter; Unit-/Protokoll-/Infrastrukturtests |
| 45 | PostgreSQL-Worker geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 46 | Heartbeats geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 47 | Leases geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 48 | Jobqueue geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 49 | Outbox geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 50 | Inventory Intake geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 51 | Inventory Processor geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 52 | CVE Collector geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 53 | CVE Enricher geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 54 | Matching Engine geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 55 | Finding Worker geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 56 | Notification Worker geprüft. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 57 | n8n-Workflow-Fortschritt berücksichtigt. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 58 | Postfix-Rückstand berücksichtigt. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 59 | Geplanter Leerlauf korrekt behandelt. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 60 | Fehlender Fortschritt korrekt behandelt. | status.sample, Collector, bestehende Health-/Jobruntime; Queue-/Leerlauf-/Freshness-/Ausfalltests |
| 61 | Healthy. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 62 | Degraded. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 63 | Unavailable. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 64 | Unknown. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 65 | Starting. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 66 | Maintenance. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 67 | Kritische Prüfungen. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 68 | Nicht kritische Prüfungen. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 69 | Abhängigkeitsaggregation. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 70 | Pipelineaggregation. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 71 | Gesamtstatus. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 72 | Keine falsche Entwarnung. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 73 | Veraltete Messwerte. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 74 | Flapping-Schutz. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 75 | Hysterese. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 76 | Rohmessungen erhalten. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 77 | Statusbegründung vorhanden. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 78 | Services persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 79 | Checks persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 80 | Observations persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 81 | Current States persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 82 | Statushistorie persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 83 | Pipelinehistorie persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 84 | Incidents persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 85 | Wartungsfenster persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 86 | Monitoringläufe persistiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 87 | Datenbankrechte minimiert. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 88 | Keine Superuserrechte. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 89 | Unique Constraints. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 90 | Indizes. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 91 | Migrationen. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 92 | Transaktionen. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 93 | Retention. | aggregation.py, Migration 00030, persist/state/incident, native PostgreSQL-/Konkurrenz-/Hysterese-/Retentiontests |
| 94 | Statusübersicht. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 95 | Serviceliste. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 96 | Servicedetails. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 97 | Historie. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 98 | Pipelineübersicht. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 99 | Incident-Liste. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 100 | Wartungsübersicht. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 101 | Authentifizierung. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 102 | RBAC. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 103 | Objektberechtigung. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 104 | CSRF für Wartungsmutationen. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 105 | Keine freie Prüfziel-API. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 106 | Kein IDOR. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 107 | Keine Secrets in Antworten. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 108 | Keine internen URLs in öffentlicher Ansicht. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 109 | Keine unkontrollierten Queue-Payloads. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 110 | Keine unberechtigten Diagnoseinformationen. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 111 | Sichere Cache-Control-Header. | router.py, bestehende AuthBoundary/RBAC, CSRF-/MFA-/Versions- und Rechteprüfungen |
| 112 | Statusübersicht. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 113 | Gesamtstatus. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 114 | Statuszeitpunkt. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 115 | Messabdeckung. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 116 | Serviceliste. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 117 | Service-Details. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 118 | Pipelineansicht. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 119 | Jobrückstand. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 120 | Datenaktualität. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 121 | Incident-Historie. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 122 | Wartungsfenster. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 123 | Statushistorie. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 124 | Diagramme. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 125 | Zugängliche Tabellenalternativen. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 126 | Responsive. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 127 | Tastaturbedienung. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 128 | Screenreader. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 129 | Keine Information ausschließlich durch Farbe. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 130 | Keine falsche grüne Anzeige bei Backendausfall. | src/status, Status-Browser und Komponententests, WCAG und responsive Screenshots |
| 131 | Incident-Erkennung. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 132 | Incident-Deduplizierung. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 133 | Incident-Historie. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 134 | Erholung. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 135 | Kein falscher Abschluss. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 136 | Wartungskennzeichnung. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 137 | Rohstatus trotz Wartung. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 138 | Benachrichtigungsintegration. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 139 | Keine Benachrichtigungsrekursion. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 140 | Keine unkontrollierte Mailflut. | Incident-/Alarm-/Wartungspersistenz, Statusalerts und Phase-19-Regression |
| 141 | Collector-Neustart. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 142 | PostgreSQL-Ausfall. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 143 | API-Ausfall. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 144 | Monitoringausfall. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 145 | Veraltete Statusinformationen. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 146 | Begrenzte Prüfparallelität. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 147 | Effiziente Datenbankabfragen. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 148 | Begrenzte Historienabfragen. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 149 | Retention. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 150 | Strukturierte Logs. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 151 | Korrelations-IDs. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 152 | Audit. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 153 | Keine Secrets. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 154 | Keine Fachdatensatzmanipulation. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 155 | Unit-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 156 | API-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 157 | PostgreSQL-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 158 | Infrastruktur-Healthtests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 159 | Worker-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 160 | Jobqueue-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 161 | Backlog-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 162 | Aggregationstests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 163 | Historientests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 164 | Incident-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 165 | Wartungstests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 166 | Sicherheitsprüfungen erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 167 | SSRF-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 168 | Konkurrenztests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 169 | Recovery-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 170 | Frontendtests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 171 | Browsertests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 172 | Accessibility-Tests erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 173 | Performance-Baseline dokumentiert. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 174 | Ende-zu-Ende-Test erfolgreich. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 175 | Dokumentation vollständig. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 176 | Übergabe an Phase 23 vorbereitet. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
| 177 | Keine unzulässigen Architekturänderungen. | Runtime-/Ausfalltests, begrenzte Datenbank-/HTTP-/Historienzugriffe, Livevergleich und Dokumentation |
