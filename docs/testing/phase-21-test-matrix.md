# Phase-21-Testmatrix

180 Kriterien aus T21.09.05. Codeprüfung und dynamische Nachweise werden gemeinsam zugeordnet; kein einzelner automatischer Fall je Kriterium wird behauptet. Berichte: .runtime/test-reports/phase-21-*.

| Nr. | Kriterium | Nachweis |
|---:|---|---|
| 1 | Bestehendes Frontend erweitert. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 2 | Kein zweites Frontend. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 3 | Bestehender FastAPI-Dienst verwendet. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 4 | Keine direkte PostgreSQL-Verbindung aus dem Browser. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 5 | Keine zusätzliche Datenbank. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 6 | Kein Redis. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 7 | Kein zusätzlicher Broker. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 8 | Kein Docker-Socket. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 9 | Keine direkte SSH-Verbindung. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 10 | Keine unzulässige n8n-Steuerung. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 11 | Bestehende Sessionverwaltung. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 12 | MFA integriert. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 13 | Same-Origin verwendet. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 14 | CSRF für sämtliche Mutationen. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 15 | Serverseitiges RBAC. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 16 | Objektberechtigung. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 17 | Keine Gruppen-ACL-Verwechslung. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 18 | Kein IDOR. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 19 | Kein Mass Assignment. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 20 | Keine Privilegieneskalation. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 21 | Kein unberechtigter Rollengrant. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 22 | Kein unberechtigter ACL-Grant. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 23 | Keine Tokens im Browserstorage. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 24 | Keine Sicherheitsgeheimnisse im Frontend-Build. | AuthBoundary, api.ts, bestehende Rechte, native/API-/Browsertests |
| 25 | Einheitliche Eingabevalidierung. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 26 | Einheitliche Fehlerdarstellung. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 27 | Keine falschen Erfolgsmeldungen. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 28 | Kritische Bestätigungen. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 29 | Schutz vor ungespeicherten Änderungen. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 30 | Versionskonflikte behandelt. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 31 | Keine stille Überschreibung. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 32 | Keine doppelten Mutationen. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 33 | Keine unkontrollierten Retries. | Form.tsx, administration.test.tsx, Browser-Konflikt-/Draft-/MFA-Fälle |
| 34 | Server erstellen. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 35 | Serverseitige UUID. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 36 | UUID unveränderlich. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 37 | Server bearbeiten. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 38 | Server archivieren. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 39 | Wiederaktivierung gemäß Vertrag. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 40 | Löschung nur bei ausdrücklicher Zulässigkeit. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 41 | Historische Daten erhalten. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 42 | Keine automatische Gruppenänderung. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 43 | Keine automatische Inventarerfassung. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 44 | Keine technische Finding-Resolution durch Archivierung. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 45 | Audit vorhanden. | Resources.tsx, bestehende Server-APIs, Serverregression |
| 46 | Gruppe erstellen. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 47 | Gruppe bearbeiten. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 48 | Gruppe entfernen gemäß Fachvertrag. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 49 | Mehrfachmitgliedschaften. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 50 | Mitgliedschaft hinzufügen. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 51 | Mitgliedschaft entfernen. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 52 | Primärgruppe setzen. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 53 | Primärgruppe validieren. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 54 | Gruppenreihenfolge ändern. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 55 | Serverreihenfolge ändern. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 56 | Tastaturalternative. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 57 | Drag-and-drop-Alternative. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 58 | Versionsschutz. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 59 | Keine implizite Rechtevergabe. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 60 | Audit vorhanden. | Resources.tsx, Ordering.tsx, Gruppen-/Sortierregression |
| 61 | Nur bestehende Server. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 62 | Berechtigte Serverauswahl. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 63 | `inventory:upload:dashboard`. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 64 | ACL `inventory_upload`. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 65 | Session und CSRF. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 66 | Vorhandener Dashboard-Uploadendpunkt. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 67 | Kein technischer Bearertoken im Browser. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 68 | Kein mTLS-Client im Browser. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 69 | Kanonisches JSON Schema. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 70 | Größenbegrenzung. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 71 | Ungültige Dateien abweisen. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 72 | Doppelte JSON-Schlüssel serverseitig abweisen. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 73 | Falsche Server-UUID abweisen. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 74 | HTTP 202 korrekt interpretieren. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 75 | Submission-ID vorhanden. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 76 | Statusabfrage vorhanden. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 77 | Verarbeitungsfehler sichtbar. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 78 | Doppelter Upload idempotent. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 79 | Kein automatisches Serveranlegen. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 80 | Keine Gruppenänderung durch Inventar. | Upload.tsx, administration.py, native echte Upload-/Processingtests |
| 81 | Triage vorhanden. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 82 | Technischer Matching-Status unveränderlich. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 83 | Bearbeitungsstatus separat. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 84 | Risikoausnahme separat. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 85 | Bearbeiterzuweisung. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 86 | Berechtigter Bearbeiter. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 87 | Notizen. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 88 | XSS-Schutz. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 89 | Fehlalarmprüfung. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 90 | Kein Matching-Overwrite. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 91 | Kompensierende Maßnahmen. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 92 | Risikoausnahmeantrag. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 93 | Genehmigungsberechtigung. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 94 | Ablaufdatum. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 95 | Widerruf. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 96 | Finding-Abschluss gemäß State Machine. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 97 | Fixnachweisvoraussetzungen. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 98 | Versionsschutz. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 99 | Audit. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 100 | Reopening bleibt möglich. | admin/Findings.tsx, unveränderte Phase-18-Commands und Findingregression |
| 101 | Benutzerliste. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 102 | Benutzer erstellen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 103 | Benutzer bearbeiten. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 104 | Benutzer aktivieren. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 105 | Benutzer deaktivieren. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 106 | Sessionauswirkungen berücksichtigt. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 107 | Keine Passwort-Hashes angezeigt. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 108 | Rollen anzeigen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 109 | Rollen zuweisen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 110 | Rollen entziehen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 111 | Effektive Rechte anzeigen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 112 | Keine Selbsteskalation. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 113 | Letzter Administrator geschützt, soweit vorgesehen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 114 | Server-ACLs anzeigen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 115 | Server-ACLs vergeben. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 116 | Server-ACLs entziehen. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 117 | Berechtigungsentzug wirksam. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 118 | Keine Gruppenberechtigungsvererbung. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 119 | MFA-Sicherheitsfunktionen nur gemäß bestehendem Vertrag. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 120 | Audit vorhanden. | Users.tsx, Account.tsx, Berechtigungsregression und ACL-Browserfall |
| 121 | Benutzerpräferenzen. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 122 | Digest-Einstellungen. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 123 | Ruhezeiten. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 124 | Pflichtmeldungen geschützt. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 125 | Regeln anzeigen. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 126 | Regeln erstellen. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 127 | Regeln bearbeiten. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 128 | Regeln aktivieren. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 129 | Regeln deaktivieren. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 130 | Regelversionen nachvollziehbar. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 131 | Keine frei ausführbaren Regeln. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 132 | Keine unkontrollierten Versandregeln. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 133 | Templates gemäß vorhandenem Backendvertrag. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 134 | Sichere HTML-Vorschau. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 135 | Keine Secrets in Vorlagen. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 136 | Keine direkte Postfix-Manipulation. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 137 | Keine direkte n8n-Manipulation. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 138 | Audit vorhanden. | admin/Notifications.tsx, bestehende Phase-19-Commands, Vorschau-/Versionstests |
| 139 | Vertrauenswürdige Actor-ID. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 140 | Audit bei Serveränderungen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 141 | Audit bei Gruppenänderungen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 142 | Audit bei Sortierung. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 143 | Audit bei Upload. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 144 | Audit bei Finding-Triage. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 145 | Audit bei Ausnahmen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 146 | Audit bei Benutzeränderungen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 147 | Audit bei Rollenzuweisungen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 148 | Audit bei ACL-Änderungen. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 149 | Audit bei Notification-Regeln. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 150 | Keine Secrets in Logs. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 151 | Keine unkontrollierte Historienlöschung. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 152 | Keine XSS-Lücke. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 153 | Kein CSRF-Bypass. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 154 | Kein IDOR. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 155 | Kein Mass Assignment. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 156 | Keine direkte Datenbankmutation aus dem Frontend. | minimierte Auditprojektion, bestehende Audit-/Scope-/CSRF-/XSS-Tests |
| 157 | Frontend-Build erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 158 | Typprüfung erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 159 | Linting erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 160 | Unit-Tests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 161 | API-Integrationstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 162 | Formularvalidierungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 163 | Authentifizierungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 164 | RBAC-Tests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 165 | Serververwaltungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 166 | Gruppenverwaltungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 167 | Sortierungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 168 | Uploadtests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 169 | Finding-Verwaltungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 170 | Benutzerverwaltungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 171 | Rollen- und ACL-Tests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 172 | Notification-Verwaltungstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 173 | Audittests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 174 | Konkurrenztests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 175 | Sicherheitstests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 176 | Browser-E2E erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 177 | Accessibility-Tests erfolgreich. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 178 | Performance-Baseline dokumentiert. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 179 | Dokumentation vollständig. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
| 180 | Keine unzulässigen Architekturänderungen. | phase-21-Check-/Browser-/Regressionsberichte und Betriebsdokumentation |
