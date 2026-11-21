# Health-Verträge

Observation trägt schema_version 1, service_id, check_id, UTC checked_at, result, duration_ms, reason_code und eine endliche Allowlist aggregierter Zahlen. Zustände healthy, degraded, unavailable, unknown und starting sind getrennt; maintenance bleibt eine zusätzliche Kennzeichnung. Liveness beweist keine Readiness, Readiness keinen Fachfortschritt. Netzwerkantworten, Payloads, Credentials, Empfänger und beliebige Details werden nicht weitergereicht. Verträge unter contracts/status und contracts/api/status.openapi.json.


Phase23 ergänzt an der API-Readinessmessung ausschließlich minimierte Prozessaggregate: api_requests, api_errors, error_rate, api_mean_latency_ms für höchstens60 Sekunden sowie collector_cpu_seconds und collector_rss_bytes. Ein leeres Zeitfenster ergibt keine erfundene Fehlerquote. Speicher und CPU bezeichnen den eigenen Collectorprozess; weder Host noch gesamter Cluster werden darüber geschätzt. Diese Rohmetriken erzeugen ohne genehmigtes Ressourcenbudget keinen automatischen Gesundheits- oder Alarmgrenzwert. Sie ersetzen nicht Liveness/Readiness oder externe Fachproben.
