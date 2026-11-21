# Worker-Performance Phase 23

PostgreSQL bleibt Jobbroker. SKIP LOCKED, gealterte Priorität, Leases, Heartbeats, Fencing, Backoff und Dead Letter bleiben erhalten. Parallelität wird nicht pauschal erhöht. Vorhandener Lasttest prüft160 eindeutige Claims bei acht Claimern mit begrenztem Pool und2250 historischen Jobs.

[Lastmodell](workload-model.md), [Budgets](acceptance-budgets.md), [Ergebnisse](performance-results.md).
