# Versionierte Workflows

`workflows/n8n` enthält 17 JSON-Definitionen: den zentralen Workflow
`cve-control-platform`, die zentrale Queue-Verarbeitung `cve-control-queue`, acht
fachliche Unterworkflows den unabhängigen Dienst-Watchdog sowie sechs Finding-Notification-Workflows für Dispatch,
Digest, Eskalation, Ausnahmen, Reconciliation und Health.

Der zentrale Workflow verarbeitet zuerst die persistente Datenbank-Queue. Der
Queue-Workflow beansprucht jeweils eine Nachricht und routet sie über sichtbare
If-Knoten als Befehl, Aufgabe, Ergebnis oder Ereignis an feste interne APIs.
Erst die quittierte n8n-Entscheidung gibt eine Aufgabe für Python-Worker frei.
Zeitpläne und authentifizierte interne Webhooks wecken die Steuerung; persistente
Deduplizierung schützt vor mehrfacher Verarbeitung.

HTTP-Ziele sind fest und TLS-geschützt. Der zusätzliche Workflow
`cve-control-watchdog` führt alle 30 Sekunden ausschließlich den parametrisierten
PostgreSQL-Aufruf `status.watchdog_tick(execution_id, workflow_id)` aus. Dafür nutzt
er TLS mit Zertifikatsprüfung und ein verschlüsseltes Credential der beschränkten
Steuerungsrolle `workflow_control`. Die gespeicherten Prüfwerte stammen vom
unabhängigen Host-Control-Agent; blockierte HTTP-Steuerdienste verhindern diesen
Pfad nicht. Es gibt keine SMTP-, Shell-, Datei- oder frei konfigurierten Code-Nodes.
Credential-Referenzen enthalten keine Werte.
Credentials werden über eine private temporäre Importdatei in n8ns verschlüsselte
Registrierung importiert; diese Datei wird anschließend gelöscht. Import und
`publish:workflow` sind gegen das gepinnte Original-Image getestet.

[Steuerungsgraph und Betrieb](../../workflows/n8n/README.md) ·
[Persistente Job-Queue](../operations/n8n-job-queue.md)

[Automatische Dienstprüfung und Prozesswiederherstellung](../operations/microservice-restarts.md)
