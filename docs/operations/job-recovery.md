# Wiederaufnahme und Dead Letters

Temporäre Fehler: exponentielles Backoff mit 80–100 % Jitter, Typ-Basis/Cap und festem
Versuchslimit. Permanent/invalid/forbidden wird nicht blind wiederholt. Failed/timed_out
sind Dead-Letter-Zustände im selben PostgreSQL-System, kein zweiter Broker.

```bash
# Nur explizit mit API-Security-Credential, keine freie SQL-/Headerautorisierung:
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage cancel --job-id <UUID>
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage replay --job-id <UUID>
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage retry-delivery --event-id <UUID> --destination <ID>
```

Replay ist nur erlaubt, wenn api_security für diesen Typ auch Produzent sein darf.
Er erzeugt eine neue Job-ID, keine stille terminale Reaktivierung. Delivery-Recovery
benötigt failed plus aktiviertes bekanntes Ziel, erhöht ausdrücklich das begrenzte
Versuchsbudget (insgesamt höchstens 100), behält Zähler/Histories und protokolliert
Actor, vorheriges/neues Limit in runtime_actions. Vor Retry Credentials/Payloadursache
und mögliche externe Seiteneffekte prüfen. Kein pauschaler Exactly-once-Anspruch.

Lease-Reaper arbeitet nur im eigenen Handlerkontext und in kleinen Batches. Besitzer-
verlust, globale Deadline und Versuchslimit bleiben historisiert; alte Tokens werden
nie wieder gültig. Bei PostgreSQL-Ausfall keine In-Memory-Fallbackqueue. Nach Recovery
normal weiterarbeiten, keine manuellen Lease-/Epoch-Resets und keine Volume-Löschung.
