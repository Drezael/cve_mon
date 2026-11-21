# Recovery der Inventarverarbeitung

Bei PostgreSQL-Ausfall wird Readiness negativ. Die vorhandene Worker-Schleife versucht
begrenzte Datenbankoperationen weiter; es gibt keine flüchtige Ersatzqueue. Nach Rückkehr
des Datenbankdienstes werden nicht abgeschlossene Leases durch Phase 7 zurückgewonnen.
Jobs behalten dieselbe Submission und nutzen ihre begrenzte Versuchszahl.

Bei Prozessabbruch vor Fachcommit rollt PostgreSQL die Snapshottransaktion zurück.
Ein gesondert gespeicherter Beginn ist kein erfolgreicher Snapshot. Nach Leaseablauf
übernimmt ein neuer Worker. Nach Fachcommit sind Snapshot, Kinddaten, Current-Pointer,
Abschlussereignisse und Jobabschluss gemeinsam persistent. Ein Neustart erzeugt keine
zweite Bestandsaufnahme. Verlorene Lease/Fencing verhindern Commits alter Handler.

Dauerhafte Vertragsfehler erhalten `rejected_after_acceptance` mit festem Code und
Fehlerereignis. Der technische Job ist damit regulär abgeschlossen: endlose Retries würden
die unveränderlichen Rohdaten nicht reparieren. Temporäre Timeout-/DB-Fehler werden durch
die vorhandene Klassifikation wiederholt. Nach Erschöpfung wird der abweichende Fachstatus
`failed` aus dem terminalen Jobzustand abgeleitet; Fehlerereignis und Jobstatus committen
zusammen. Keine vollständigen Validatornachrichten oder Tracebacks in Benutzerantworten.

Zuerst privaten Dienstzustand, `manage metrics`, `manage submission --id ...` und die
Phase-7-Versuchshistorie prüfen. `manage verify` überprüft gespeicherte Objektanzahlen.
Current-Pointer über `manage current` und den deterministischen Auswahlvertrag prüfen.
Originalbytes und bestehende Credentials nicht durch Debug-Ausgaben offenlegen.

Backups und isolierte Restoreprüfung erfolgen unverändert über die Phase-3-Werkzeuge.
Snapshottrigger sind nach dem Restore aktiv; der PostgreSQL-Dump lädt Daten vor dem
Anlegen der Trigger. Nie manuell einzelne Kindtabellen als Reparatur überschreiben.
Keine automatische Retention, kein Löschen von Originalen oder historischen Beständen.
