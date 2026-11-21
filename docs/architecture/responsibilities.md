# Verantwortlichkeiten und Datenhoheit T00.01.03

| Schreibvorgang | Verantwortlicher Kontext | Explizit ausgeschlossen |
|---|---|---|
| CVE-Originale und Revisionen | cve-importer | Dashboard, n8n, Matcher |
| Hersteller-/Quellenergänzungen | cve-enricher | Umschreiben von CVE-Originalen |
| Inventarannahme, Receipt und Job | cve-api / api_ingest, für beide Uploadwege | Serveranlage, Stammdaten, Gruppen, Sortierungen |
| Software-/Inventarnormalisierung | cve-inventory / inventory_processor | Administrative Server-, Gruppen- und Sortierdaten |
| Server registrieren, bearbeiten, archivieren, wiederherstellen | cve-api / dashboard_admin nach menschlicher Autorisierung | Upload-Token, Inventory Processor, n8n |
| Gruppen, Mitgliedschaften, Primärgruppe, manuelle Reihenfolgen | cve-api / dashboard_admin | Uploads, Matcher, Event Dispatcher, n8n |
| Matching-Ergebnisse | cve-matcher | Finding-Status und administrative Daten |
| Finding-Status, Risiko, Historie | cve-findings mit geprüftem Actor-Kontext | Matcher schreibt keine Findings direkt |
| Benutzer, Rollen, Rechte, Sitzungen, MFA | cve-api / api_security (administrative Prüfung getrennt) | Technische Upload-Identitäten |
| Berichte | cve-reporter | Änderungen an Bewertungsgrundlagen |
| Outbox-Ereignis erzeugen | Zuständiger Fachschreiber in derselben Transaktion | Lose gekoppelte, nicht atomare Nachträge |
| Ereignis zustellen | cve-event-dispatcher | Erfinden von Gruppenbefehlen aus Inventaren |
| Benachrichtigung zustellen | cve-notification, anschließend Postfix | n8n mit direkten SMTP-/DB-Sonderrechten |

Das Dashboard ist der autorisierte menschliche Verwaltungskanal, cve-api führt seine
Verwaltungsoperationen aus. Es erhält keinen universellen DB-Benutzer für alle Kontexte:
getrennte Pools/Rollen, kein frei wählbarer Rollenname aus Request-Feldern und keine Rolle,
die mittels SET ROLE von api_ingest zu dashboard_admin wechseln darf.

Objektberechtigungen werden am API-Rand und am schreibenden Fachdienst geprüft. Der Gatewayschutz
ersetzt keine Fachautorisierung. Interne Dienstidentität und menschlicher Actor bleiben getrennt.
Auditfelder und Upload-Herkunft stammen aus vertrauenswürdiger Annahme, niemals aus Inventar-JSON.
