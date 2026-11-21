# Eingeschränkte n8n-Laufzeit

Das unveränderte Herstellerimage `n8nio/n8n:2.46.7` wird per Digest aus
`../images.lock.json` bezogen. Es gibt keinen eigenen n8n-/Node-Build und keine
npm-Overrides. PostgreSQL, HTTPS, freigegebene Knotentypen und deaktivierte UI,
öffentliche API sowie Communitypakete sind fest in Compose konfiguriert.

Compose startet den read-only eingebundenen Wrapper `start.sh`. Er führt vor dem
Hersteller-Entrypoint `/docker-entrypoint.sh` den `bootstrap.cjs` aus. Der Bootstrap
verwendet dieselben Import- und Veröffentlichungsfunktionen wie die CLI der
festgelegten n8n-Version und initialisiert deren Module einmal pro Start.
Diese versionsgebundene Integration muss bei einem Imagewechsel erneut mit dem
Originalimage getestet werden; eine andere Version wird abgewiesen.

Alle Definitionen aus `workflows/n8n/*.json` sind unter `/opt/cve-workflows`
read-only eingebunden. Der Bootstrap validiert die Definitionen und die private
Credential-Datei `/run/cve-n8n/credentials.json`, importiert sie und veröffentlicht
jede verwaltete Workflow-ID. Erst bei vollständigem Erfolg startet der Server.
Fehler beenden den Container mit Fehlerstatus; eine fehlerhafte Definition wird
nicht als gesunder Serverstart ausgegeben. Beim nächsten Versuch wird der gesamte
Abgleich wiederholt. Es erfolgt keine Löschung fremder Workflow-/Credential-IDs.

Workflow-Definitionen und deren Veröffentlichung werden bei jedem Containerstart
aktualisiert, einschließlich Docker-Restarts. Das Argument zur ausdrücklichen
Erstinitialisierung entfällt. Anwendungszeitpläne und Pause-Einstellungen in der
Anwendungsdatenbank sowie der persistente n8n-Verschlüsselungsschlüssel bleiben
bestehen. Code, feste Definitionen und Bootstrap werden im Repository gepflegt;
interne Pfade sind keine `.env`-Optionen.

Siehe [Workflow-Betrieb](../../workflows/n8n/README.md) und
[Betrieb der Original-Images](../../docs/deployment/upstream-images.md).
