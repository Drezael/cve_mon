# Übergabe an Phase 20/21/22

API 0.19.0 liefert persönliche Intents, Statushistorie, Zustellversuche, aktuelle Präferenzen,
versionierte Regeln/Templates sowie privilegierte Workflow-/Delivery-Ansichten. Der Vertrag
liegt in contracts/api/notification-management.openapi.yaml. Die Oberfläche bleibt Aufgabe
der folgenden Phasen; Berechtigungsprüfung ist weiterhin serverseitig verbindlich.

Eine Notification ist keine Finding-Zustandsänderung. Digest-Mitglieder referenzieren einen
Elternauftrag mit eigenem Zustellstatus. relay_accepted und upstream_accepted sind keine
finale Zustellung. submission_uncertain blockiert Resubmits bis zu vertrauenswürdiger
Reconciliation. Eine Statuspage muss diese Zustände und unbekannte/stale Queue-Messwerte
getrennt darstellen; ein gesunder n8n-Prozess genügt nicht als Zustellnachweis.

Auslieferung: n8n Regular Mode, Fach-DB-Head 00027, notification/api 0.19.0. Keine neuen
Kanalarten, n8n-Fach-DB-Verbindungen oder allgemeinen Versand-Callbacks ergänzen. Normale
Regeln und Mailfreigaben sind anfangs geschlossen; keine Testempfänger aus Fixtures übernehmen.
