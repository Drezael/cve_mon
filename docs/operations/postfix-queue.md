# Queue-Wartung

`make mail-queue`: native JSON-Queue mit Queue-ID, Zustand und Adressen, nur für
Administratoren. `make mail-flush`: nativen Retry auslösen, nicht automatisch alle
Fehlerzustände überspringen. Kein postsuper-Massenlöschen im Normalbetrieb.
Deferred-Alter/Anzahl/DSN, freien Speicher, Limits und Schreibfähigkeit überwachen.
[Aufbewahrung, Bounces, Backpressure und Backup](postfix-backup-restore.md).

Der native JSON-Queuebericht stellt den leeren Envelope-Sender von Rückläufern als
`MAILER-DAEMON` dar; auf dem SMTP-Protokoll bleibt er korrekt `MAIL FROM:<>`.
