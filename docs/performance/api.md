# API-Performance Phase 23

Die SQL-Optimierung wirkt im bestehenden Authkontext; doppelte Sicherheitsprüfung an Router und Service bleibt erhalten. Keine Session-/RBAC-Caches, keine neuen Workerprozesse und kein unbegrenzter Pool. No-store und berechtigungssichere Counts werden regressionsgeprüft.

[Lastmodell](workload-model.md), [Budgets](acceptance-budgets.md), [Ergebnisse](performance-results.md).
