# Abhängigkeiten, Offlinefähigkeit und Wiederanlauf T00.01.05

| Ausfall | Betroffen / weiter verfügbar | Fehler und Wiederanlauf | Persistenz / Wiederholung |
|---|---|---|---|
| PostgreSQL | Login, Annahme, Fachjobs blockiert; Prozess-Liveness möglich | 503, keine Annahmequittung vor Commit; Readiness false | Keine In-Memory-Ersatzqueue; Client wiederholt mit gleicher inventory_id |
| n8n | Neue orchestrierte Folgejobs verzögert; Suche, lokale APIs und vorhandene Workerjobs bleiben | Dispatcher liefert später erneut | Outbox/Jobs bleiben in PostgreSQL; Event-ID deduplizieren |
| Envoy | Import/Anreicherung und SMTP-Uplink gestört; lokale Suche/Matching nutzbar | Quellenalter anzeigen, kein direkter Internet-Fallback | Persistente Jobs mit Backoff; Postfix puffert |
| Postfix | Versand verzögert; Findings/Reports/Inventare bleiben nutzbar | Notification-Job erneut zustellen, Annahme nicht vortäuschen | Benachrichtigungsstatus persistent; begrenzte Retrys |
| Internet | Externe Quellen und SMTP gestört; lokale CVE-Suche, Inventare, Benutzerverwaltung und Matching bleiben | Offline-/Freshness-Zustand ausweisen | Vorhandene Originaldaten/Revisionen bleiben lokal |
| Einzelne CVE-Quelle | Nur Aktualität dieser Quelle reduziert | 429/Retry-After respektieren; keine Löschung alter Daten | Quellencursor erst nach vollständigem Commit fortschreiben |
| cve-inventory | Validierte Annahme möglich, Verarbeitung queued | 202 bleibt Annahme, kein Verarbeitungsversprechen | Jobs/Originale persistent; abgelaufene Lease erneut übernehmen |
| cve-matcher | Neue Bewertung verzögert; gespeicherte Ergebnisse lesbar | Bewertungsalter anzeigen | Idempotenter Lauf mit Snapshot-/Regelrevision |
| cve-dashboard | Oberfläche/integrierte Statuspage nicht erreichbar; technischer Upload weiter möglich | Nginx 502/504, keine unabhängige Statuspage versprechen | Sitzungen bleiben serverseitig; keine Browserqueue als Datenquelle |
| cve-api | Uploads, Anmeldung und Statuspage blockiert; bestehende Worker arbeiten weiter | Nginx 502/504; technische Clients wiederholen mit gleicher Identität | Kein Erfolg vor Annahme-Commit |
| cve-service-status | Statusseite liefert 503; Fachfunktionen bleiben | Kein alter Status als aktueller Ersatz | Kein Statuscache; nächster Seitenaufruf prüft neu |

Jobs verwenden Lease/Fencing und exponentiellen Backoff mit Jitter: 5 s bis 15 min,
maximal 10 Versuche; danach failed/dead zur administrativen, auditierbaren Wiederholung.
Quellen-429 kann den nächsten Termin gemäß Retry-After verschieben. Lease 120 s,
Heartbeat alle 30 s; fachlich lange Jobs müssen regelmäßig erneuern oder segmentieren.
Dies sind Spezifikationswerte, in späteren Lasttests überprüfbar und nur versioniert änderbar.
Postfix hat eine persistente Queue; geplanter maximaler Queue-Aufenthalt 5 Tage,
anschließend Bounce/Fehlerstatus, Überwachung von Alter/Größe. Unbegrenzte Pufferung wird nicht zugesagt.

Backup/Restore muss Datenbank, lokale Berichtartefakte, Postfix-Queue sowie separat gesicherte
MFA-Schlüssel berücksichtigen. Kein RPO/RTO ohne spätere Messung; Wiederherstellung wird getestet.
