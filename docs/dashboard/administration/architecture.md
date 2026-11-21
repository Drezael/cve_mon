# Architektur

Bestehendes React/TypeScript/Vite-Frontend unter services/dashboard, bestehender Nginx und cve-api 0.21.0. Keine neue Fach-API und kein Node-Produktivdienst. src/admin enthält explizite Fachformulare; src/api.ts transportiert ausschließlich Same-Origin-Anfragen. Kein freier Endpunkt-/JSON-Kommandoeditor. Neue Lese-Endpunkte unter /api/v1/dashboard/administration ergänzen Auswahllisten, Verarbeitungsstatus, Versionshistorien, Vorlagenvorschau und minimierte Audit-Metadaten. Migration 00029 ergänzt ausschließlich ein unveränderliches Audit-Leseview und dessen/Processing-Leserechte. Keine fachlichen Tabelleninhalte werden migriert.

## Gemeinsame Einstellungen

Die Oberfläche führt persönliche und instanzweite Einstellungen unter `/settings/*` zusammen. Die Navigation enthält nach Berechtigungsfilterung: Dashboards, Übersicht, Server, Gruppen, Findings, Einstellungen, Systemstatus. Administration ist kein separater Navigationseintrag mehr. Die Überschrift und der Brotkrümel „Arbeitsbereich“ entfallen.

Jeder Einstellungsbereich hat weiterhin seine eigene Berechtigung. Konto und Sprache sind für angemeldete Benutzer verfügbar; Mail und Benachrichtigungen benötigen `notification:read`. Benutzerliste, Rollen, zentrale SMTP-Konfiguration, Instanzeinstellungen, Versandregeln, Vorlagen und Audit werden nur mit der jeweils passenden Berechtigung angezeigt. Nicht berechtigte direkte Seitenaufrufe werden vor dem Laden von Daten abgefangen. Benutzerdetails setzen zusätzlich `user:read` voraus. Auch eine Administratorrolle ersetzt keinen fehlenden Berechtigungseintrag.

Alte Browserlinks `/administration/*` leiten einschließlich Suchparametern und Fragment nach `/settings/*` weiter. Die bestehenden geschützten API-Pfade bleiben gültig; ihre serverseitigen Prüfungen gelten unabhängig von der Navigation.
