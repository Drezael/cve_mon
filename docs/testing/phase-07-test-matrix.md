# Phase-7-Testmatrix

| Bereich | Praktischer Nachweis |
|---|---|
| Verträge | strikte Pydantic-/JSON-Schemas, rekursive Secret-/Steuer-/URL-Verbote, Versionen, Größen |
| Registry | nur explizite Callables, unknown/duplicate abgelehnt, kein Codeimport aus Payload |
| Enqueue | parallele gleiche Schlüssel → eine ID; abweichende Anforderung → Konflikt |
| Claim/Fence | echte PostgreSQL-SKIP-LOCKED-Parallelität, verschiedene IDs, Token/Epoch/Ablauf |
| Historie | Versuch je Reservierung, Lease-Verlust, Erfolg/Retry/Fehler, keine Gegenbuchung alter Tokens |
| Worker | isolierte Tasks, Retry trotz fehlerhaftem Handler, begrenzte Slots, Shutdown |
| Prozesse | reale SIGKILL vor Handler und nach DB-Effekt, SIGTERM, anschließende Übernahme |
| Datenbankeffekt | stale context.atomic rollt zurück; context.complete koppelt Effekt und Erfolg |
| Retry/Frist | begrenzte Versuche/Backoff/Jitter, endgültiger Fehler, wartende Deadline abgelaufen |
| Outbox | Business + Event committen/rollen zusammen zurück; unveränderliche Identität |
| Dispatcher | echter Dockerprozess und authentifizierter HTTPS-Empfänger, SNI/CA/Token |
| Fehler | 401/400/302/falsches Zertifikat, 503, unsichere Ack-Wiederholung, DB-Ausfall/Neustart |
| Zustellung | keine DB-Zeilenlocks bei langsamem HTTPS; reale SIGKILL-Übernahme und stale Ack abgelehnt |
| Consumer | parallele Deduplizierung, fehlgeschlagener erster Versuch blockiert Wiederholung nicht |
| Reihenfolge | ältere Version blockiert neuere; verspätete niedrigere Version abgelehnt |
| Rechte | managed Direktwrites, fremder Claim/Consumer und Gruppenwrites abgelehnt |
| Kontrolle | Replay mit neuer ID; Delivery-Retry mit auditierter Budgeterweiterung ohne Zählerreset |
| Performance | 2.250 gemischte Jobs, 225 aktiv, 160 Claim/Finish, 8 Claimers/Pool 5, Indexplan/Fairness |

`make jobs-test jobs-security jobs-concurrency-test outbox-test outbox-security dispatcher-test`
oder Gesamtlauf `make automation-integration`. Standardtests über make check.
Regressionen: db-test, infra-test, envoy-test, postfix-test, services-integration.
Alle Daten in eigenen UUID-Projekten mit realem PostgreSQL; kein SQLite-Ersatz und
keine produktiven Jobs/externen Empfänger. Cleanup prüft Projekt-/Volumeeigentümer.
