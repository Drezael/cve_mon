# Phase-23-Kontrollmatrix

137 verbindliche Kontrollen. Zuordnung benennt tatsächliche Implementierungen/Prüfgruppen; erfolgreiche Einzelnachweise werden nur anhand vorhandener Berichte behauptet. Offene Imagebefunde verhindern Gesamtabnahme.

| Nr. | Kontrolle | Implementierung / Prüfung |
|---:|---|---|
| 1 | Keine unerforderlichen öffentlichen Ports. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 2 | Keine Docker-Socket-Mounts. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 3 | Keine unnötigen privilegierten Container. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 4 | Minimierte Linux Capabilities. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 5 | Aktive Seccomp-Schutzwirkung. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 6 | No New Privileges, soweit kompatibel. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 7 | Unprivilegierte Dienstprozesse, soweit kompatibel. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 8 | Dokumentierte Schreibpfade. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 9 | Minimale Bind-Mounts. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 10 | Geprüfte Netzwerkisolation. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 11 | Kein direkter Egress-Bypass. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 12 | Keine ungeschützten Adminschnittstellen. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 13 | Ressourcenlimits dokumentiert. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 14 | Container-Neustartverhalten geprüft. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 15 | HTTPS funktioniert. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 16 | TLS-Zertifikate gültig. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 17 | Unsichere Zertifikate werden abgewiesen. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 18 | mTLS funktioniert. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 19 | Unbekannte Clientzertifikate werden abgewiesen. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 20 | Abgelaufene Zertifikate werden abgewiesen. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 21 | Zertifikatswiderruf funktioniert. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 22 | Technische Tokens sind korrekt gebunden. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 23 | Server-Scopes können nicht überschritten werden. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 24 | Forwarded-Header werden kontrolliert. | Composevalidator; tests/infrastructure; phase-23-containers/networks |
| 25 | Login geschützt. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 26 | MFA geschützt. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 27 | Session Fixation geprüft. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 28 | Logout invalidiert Session. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 29 | Benutzerdeaktivierung wirksam. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 30 | CSRF wirksam. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 31 | Kein IDOR. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 32 | Kein Mass Assignment. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 33 | Kein SQL Injection. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 34 | Kein XSS. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 35 | Kein SSRF. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 36 | Keine unberechtigte Rollenänderung. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 37 | Keine unberechtigte ACL-Änderung. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 38 | Keine unberechtigten Serverdaten. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 39 | Keine unberechtigten Findingdaten. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 40 | Berechtigungssichere Aggregationen. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 41 | Requestlimits. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 42 | Rate Limits. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 43 | Keine vertraulichen Stacktraces. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 44 | Keine Secrets in API-Antworten. | auth/authorization/inventory/dashboard/status; phase-23-api/auth/rbac/uploads/frontend/resilience |
| 45 | Minimale Datenbankrechte. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 46 | Keine unnötigen DDL-Rechte. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 47 | Kein Anwendungs-Superuser. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 48 | Schema-Berechtigungen korrekt. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 49 | Datenbanktrennung n8n. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 50 | Sichere Verbindungskonfiguration. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 51 | Fremdschlüssel konsistent. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 52 | Unique Constraints wirksam. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 53 | Snapshot-Unveränderlichkeit. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 54 | Matching-Integrität. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 55 | Finding-Historie. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 56 | Audit. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 57 | Idempotenz. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 58 | Atomare Transaktionen. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 59 | Keine unkontrollierte Cascade-Löschung. | Migrationen, Rollen, Constraints; phase-23-database/recovery/pipelines |
| 60 | Technischer Upload autorisiert. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 61 | Dashboard-Upload autorisiert. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 62 | Nur registrierte Server als Uploadziel. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 63 | JSON Schema validiert. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 64 | Doppelte JSON-Schlüssel abgewiesen. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 65 | Überdimensionierte Dateien abgewiesen. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 66 | Keine Gruppenänderung durch Upload. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 67 | Kein ACL-Grant durch Upload. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 68 | HTTP 202 korrekt. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 69 | Keine doppelten Snapshots. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 70 | CVE-Quellen validiert. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 71 | Kein SSRF durch CVE-Quellfelder. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 72 | Quellenprovenienz erhalten. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 73 | Debian-Versionen korrekt. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 74 | Unknown korrekt. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 75 | Keine falsche Entwarnung. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 76 | Matching-Ergebnisse konsistent. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 77 | Keine doppelten Findings. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 78 | Finding-Reopening korrekt. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 79 | Keine doppelte Notification. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 80 | Unklare SMTP-Übergaben korrekt. | Inventory/Importer/Enricher/Matching/Findings/Notification; phase-23-uploads/pipelines |
| 81 | Reproduzierbare Baseline. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 82 | Dokumentierte Testdaten. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 83 | API-Latenz gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 84 | PostgreSQL-Queryzeiten gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 85 | Uploadverarbeitung gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 86 | CVE-Import gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 87 | Enrichment gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 88 | Matching gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 89 | Finding-Verarbeitung gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 90 | Notification-Verarbeitung gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 91 | CPU gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 92 | RAM gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 93 | Datenbankverbindungen gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 94 | Queue-Rückstände gemessen. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 95 | p95/p99 dokumentiert. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 96 | Keine fachliche Regression. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 97 | Keine unkontrollierte Parallelität. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 98 | Keine Retry-Stürme. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 99 | Keine Cache-Leaks. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 100 | Performancebudgets überprüft. | workload + bestehende Durchsatzfälle; phase-23-performance/workers/frontend |
| 101 | Workerabsturz vor Commit. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 102 | Workerabsturz nach Commit. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 103 | Verlorene Lease. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 104 | Verspäteter Worker. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 105 | PostgreSQL-Neustart. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 106 | Envoy-Ausfall. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 107 | n8n-Ausfall. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 108 | Postfix-Ausfall. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 109 | API-Ausfall. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 110 | Nginx-Ausfall. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 111 | Volles Dateisystem. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 112 | Volle Datenbank. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 113 | Backpressure. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 114 | Outbox-Wiederaufnahme. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 115 | Keine verlorenen Audit-Ereignisse. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 116 | Keine doppelten fachlichen Effekte. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 117 | Backupintegrität. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 118 | Isolierter Restore. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 119 | Rollback-Verfahren. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 120 | Dokumentierte RPO/RTO-Bewertung. | tatsächliche Worker-/Containerstörungen, Tablespace-ENOSPC und verschlüsselter Restore; phase-23-resilience/recovery |
| 121 | Reproduzierbare Builds. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 122 | Dependency Lockfiles. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 123 | Image-Inventar. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 124 | SBOM. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 125 | Dependency Scanning. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 126 | Image Scanning. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 127 | Secret Scanning. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 128 | Bewertete Sicherheitsbefunde. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 129 | Bedrohungsmodell. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 130 | OWASP-Kontrollmatrix. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 131 | Sicherheitsbaseline. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 132 | Performancebaseline. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 133 | Lasttestergebnisse. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 134 | Recoverynachweise. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 135 | Restrisikoregister. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 136 | Vollständige technische Dokumentation. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
| 137 | Übergabe an Phase 24. | supply_chain.py, SBOMs, Gates, Provenienz, Dokumentation; keine Freigabe bei offenen Befunden |
