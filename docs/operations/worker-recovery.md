# Unabhängige Prozessneustarts und dauerhafte Wiederaufnahme

Die neun eigenen Microservices laufen weiterhin in drei Anwendungscontainern.
Ein Neustart über den Systemstatus läuft als Auftrag durch n8n und ersetzt nur den
gewählten Python-Prozess. Der Container und andere Prozesse laufen weiter.
Der Supervisor bearbeitet verschiedene Rollen parallel; ein nicht reagierender
Dienst hält den Start einer anderen Rolle nicht auf. Der Hostcontroller lässt
solche Neustarts parallel zu, während Backups und Serverlöschung exklusiv bleiben.

## Behobener Importfehler

Ein abgeschlossener Auftrag verliert seine Lease absichtlich beim atomaren Commit.
Zuvor konnte der Heartbeat dies während der anschließenden Parser-Bereinigung als
Leaseverlust behandeln und die Bereinigung abbrechen. Die Git-Sperre blieb dadurch
im Prozess offen. Weitere Importe scheiterten mit `TEMPORARY`, obwohl der Dienst
technisch erreichbar war.

Die Heartbeat-Logik berücksichtigt nun atomaren Abschluss und Nachbereitung.
Parser-Pools werden auch bei Abbruch begrenzt beendet und ihre Kinder eingesammelt,
bevor die Git-Sperre freigegeben wird. Eine blockierte Git-Sperre wird ausdrücklich
als `GIT_CACHE_BUSY` diagnostiziert. Rohmeldungen und Zugangsdaten werden nicht geloggt.

## Wiederaufnahme

Jeder Job-Worker registriert beim Start einen dauerhaften `worker.recover`-Auftrag
in PostgreSQL. Er wartet beim technischen Start nicht auf dessen Ausführung.
Nur der zentrale n8n-Queue-Consumer darf die Wiederaufnahme freigeben. Der Worker
kann ausschließlich seine registrierten Jobtypen anmelden. Nach dem Ablauf einer
verwaisten Lease wird ebenfalls ein Recovery-Auftrag erstellt.

Wiederholt werden vorübergehende Netzwerk-, Datenbank-, Timeout-, Lease- und
Shutdown-Fehler. Bewusst abgebrochene oder pausierte Workflows und dauerhafte
Validierungs-/Berechtigungsfehler werden nicht automatisch erneut ausgeführt.
Wiederholungen erhalten einen neuen Job mit `replay_of` auf den alten Versuch.
Doppelte Boot- oder Recovery-Anforderungen erzeugen keine doppelten Replays.
Große Rückstände werden über begrenzte n8n-Folgeaufträge abgearbeitet.

Beim CVE-Import wird nur der neueste fehlgeschlagene Lauf einer aktivierten Quelle
wieder aufgenommen. Derselbe Importlauf behält Manifest, gepinnten Git-Commit,
Batch-Offset und bereits gespeicherte Datensätze. Ältere überholte Importläufe
werden nicht zusätzlich vollständig verarbeitet. Import- und Jobstatus werden
synchronisiert, damit ein fehlgeschlagener Auftrag keinen laufenden Import vortäuscht.

Fehlversuche, Diagnosecode und Fehlerklasse bleiben in `automation.jobs` und
`automation.job_attempts` erhalten. Die Start-/Freigabebelege stehen in
`automation.worker_recoveries` und `automation.n8n_queue`. Es werden keine
Fehlerhistorien gelöscht, um einen gesunden Status zu erzwingen.
Nach erfolgreicher Wiederaufnahme zählen behobene Fehler nicht mehr als aktuelle
Störung. Ein CVE-Import bleibt bei überfälligen Quelldaten eingeschränkt, bis die
Daten tatsächlich erfolgreich aktualisiert wurden.

## Prüfung

- `tests/unit/test_worker_completion_cleanup.py`: Reproduktion des Heartbeat-/Git-Lock-
  Fehlers sowie sichere Bereinigung bei Abbruch.
- `tests/orchestration/test_worker_recovery.py`: echte n8n-Freigabe, Wiederaufnahme
  eines gespeicherten Git-Checkpoints und unabhängige Prozessneustarts bei einem
  absichtlich gestoppten Nachbardienst.
- Die vorhandenen Git-Import-, Job-Fencing- und Worker-Lifecycle-Tests gelten weiter.

Ein ausdrücklich angeforderter CVE-Reset darf die geteilte n8n-Queue nicht über
`TRUNCATE`-Abhängigkeiten leeren. Der Operator-Reset entfernt nur geprüfte CVE-
Laufzeitdaten und die zugehörigen Queue-Zeilen; SMTP-Einstellungen und andere
Steueraufträge bleiben erhalten. Dieser Vorgang wird nicht bei Neustarts ausgeführt.
