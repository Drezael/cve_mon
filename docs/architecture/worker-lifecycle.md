# Worker-Lebenszyklus und Fencing

WorkerSettings erweitert die Phase-6-Settings: begrenzte Parallelität/Batchgröße,
Lease, Heartbeat, Polling, Pause und Shutdown. Standard: zwei aktive Jobs, Batch zwei,
Pool drei, Lease 15 s, Heartbeat 3 s, Poll 0,5 s, Grace 5 s. Heartbeat höchstens Lease/3,
Parallelität kleiner als Poolgröße. Freie Slots begrenzen die Reservierung; keine
unbegrenzten Tasks oder Vorabreservierungen. Leere/fehlerhafte Queue pausiert.

Jeder Versuch erhält eigene Task, validierte Payload, Korrelationskontext und eigene
Sessions. Ein fehlgeschlagener Handler beendet nicht den Loop. Request-ID wird nicht
von einem fremden HTTP-Kontext geerbt. Logs zeigen ausschließlich sichere IDs und
stabile Ereignis-/Fehlerkategorien, keine Payloads/Lease-Tokens/Exceptiontexte.

## Lease und Deadline

Owner-UUID + zufälliges Token + monotoner Fencing-Epoch müssen übereinstimmen.
PostgreSQL clock_timestamp entscheidet über Ablauf, nicht Containeruhren. Heartbeat
verlängert nur gültige eigene Leases, begrenzt durch Ausführungs-/Gesamtdeadline.
Eine verlorene Lease stoppt die Task. Unvollständige/späte Ergebnisse werden abgewiesen.
Lease-Ablauf und Laufzeitüberschreitung sind verschieden; Recovery historisiert einen
verlorenen Versuch und plant einen begrenzten Retry oder einen terminalen Zustand.

`ExecutionContext.atomic()` prüft am Transaktionsende das aktuelle Fence unter Lock;
veraltete DB-Effekte rollen zurück. `context.complete(operation)` validiert das Ergebnis
und committet Business-Effekt, mögliche Outbox und Joberfolg in EINER Transaktion.
Hier keine externen Warteoperationen ausführen. Für externe Effekte ist zusätzlich
Idempotenz erforderlich; keine pauschale Exactly-once-Zusage.

SIGTERM: Annahmestopp, Stop-Event, begrenztes Drain, dann Task-Cancel und Retry oder
Lease-Ablauf. Ressourcen erst nach Loop/Tasks schließen. SIGKILL benötigt keine
Aufräumaktion: persistente Lease verfällt, neuer Worker erhält neues Fence. Reale
Subprozess-SIGTERM/SIGKILL-Tests vor Handlerbeginn und nach DB-Effekt belegen Recovery.

[Fehler/Recovery](../operations/job-recovery.md), [Sicherheit](../security/job-execution-security.md).
