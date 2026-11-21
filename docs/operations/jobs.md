# Jobs und technische Inspektion

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage jobs
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage outbox
CVE_DOCKER_SUDO=1 make jobs-check automation-integration
```

Inspektion verwendet reporter, maximal 100 Datensätze (CLI default 50), feste Queries,
keine Payloads/Secrets und keine freie SQL-Eingabe. Metriken über status_probe oder
internen Dispatcher-/metrics-Endpunkt: Statuszahlen, älteste Wartedauer, abgelaufene
Leases, durchschnittliche Versuchsdauer, Fehler-/Retryrate, Outbox-Backlog/-Alter und
Zustellfehlerrate. Alte nicht aktivierte Datensätze werden gesondert gezählt.

Registrierter Job: striktes Payload-Modell, Resultatmodell, Callable, Runtime-/Retrylimit
und autorisierte DB-Katalogdefinition. Native Producer-Enqueue und Handler müssen
innerhalb ihrer bereits zulässigen Fachrechte bleiben. Beispiel ausschließlich in
Tests; kein produktiver Testjob oder allgemeiner Jobdaemon.

Aufbewahrung vor Produktion festlegen: aktive Jobs/Events nicht löschen. Terminale
Jobs/Versuche und Consumer-IDs mindestens über den fachlichen Replay-/Auditzeitraum
bewahren; Events, Zustell- und Kontrollhistorien append-only archivieren. Erst nach
geprüftem, berechtigtem Retentions-/Backupplan bereinigen; Phase 23 konkretisiert
Produktivfristen. Keine automatische Löschung in dieser Phase.
