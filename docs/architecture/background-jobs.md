# Persistente Hintergrundjobs

PostgreSQL automation bleibt die einzige Queue. cve_common 0.7.0 enthält technische
Registry, Verträge, Repository, Worker, Fehler und Retry; cve-api und Dispatcher
verwenden ebenfalls 0.7.0. Phase 14 registriert ausschließlich inventory.process_submission im vorgesehenen Dienst
cve-inventory; weitere fachliche Handler folgen später.
Kein Broker, Redis, allgemeiner Jobcontainer oder Workflow-DAG; n8n folgt in Phase 19.

## Vertrag und Annahme

Ein Jobtyp bindet Name/Version, striktes Pydantic-Payloadmodell, Callable, Ergebnis-
modell, Laufzeit und Versuchslimit. Nur Callables aus dem eigenen vertrauenswürdigen
Code, niemals Modul-/Shellnamen aus Daten. PostgreSQL job_types bindet dazu Handler-
und Produzentenrolle, aktive Payloadversion, Laufzeit und begrenzte Retryparameter.
Producer und Worker validieren; die DB prüft Rolle, Version, Größe, Steuer-/Secretfelder
und Versuchslimit erneut. Maximal 16 KiB Payload, Priorität -100 bis 100, 1–100 Versuche
und höchstens der Jobtypgrenze (Default 3). Unknown-Versionen führen zu keiner Codeausführung.

`JobRepository.enqueue(session, JobEnvelope(...))` verwendet die bestehende Transaktion.
Angenommen ist ein Job erst nach deren Commit. Keine flüchtige Fallbackqueue.
Idempotenz: Produzentenrolle + Scope + Jobtyp + Schlüssel; identischer kanonischer
Request liefert dieselbe ID, abweichende Payload/Version/Priorität/Frist/Versuchslimit
führt zum Konflikt. Parallelität wird durch den vorhandenen Unique-Key abgesichert.
Generierte UUIDs/Korrelation ändern nicht die fachliche Requestidentität.

## Zustände

pending → queued durch ausdrückliche Freigabe; queued/retry_pending → running durch
atomare Reservierung. Running → succeeded/retry_pending/failed/timed_out/cancelled.
Terminale Jobs gelangen nie durch normalen Claim zurück. Replay erzeugt eine neue
Job-ID mit replay_of; alte Daten und Versuche bleiben bestehen. Freigabe/Abbruch/
Replay sind nur als ausdrücklich berechtigte api_security-Operation möglich.
Wartende Jobs werden sofort abgebrochen, laufende erhalten cancel_requested;
Heartbeat-/Abschlussprüfung und kooperatives Task-Cancel respektieren das Signal.

## Claim und Fairness

Kurze Transaktion, FOR UPDATE SKIP LOCKED, Update der Lease und Einfügen des Versuchs,
Commit, erst danach Handler. Datenbankzeit ist maßgeblich. Fällige alte Jobs nach
60 Sekunden haben Vorrang nach Alter; jüngere werden nach Priorität/Zeit/ID sortiert.
Dadurch verdrängt kontinuierliche hohe Priorität nicht dauerhaft ältere niedrige.
Vergangene gewünschte Freigabezeiten werden bei Erstellung auf DB-Jetzt begrenzt.

[Worker](worker-lifecycle.md), [Schema](../database/automation-runtime.md),
[Verträge](../../contracts/jobs/job-envelope-v1.schema.json).
