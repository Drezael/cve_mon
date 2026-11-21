# Phase-7-Performance und Fairness

Lokaler Messlauf am 06.11.2026 mit echtem isoliertem PostgreSQL 18.6; technischer
Claim-/Finish-Pfad, keine Fachhandler und keine Aussage zu einem Produktions-SLA.

| Messgröße | Ergebnis |
|---|---|
| Vorbereitete historische/aktive Datensätze | 2250 |
| Davon aktive Queueeinträge | 225 |
| Zusätzlich überalterter Eintrag | niedrige Priorität, zuerst reserviert |
| Parallele Claimers / Poolmaximum | 8 / 5 |
| Erfolgreiche eindeutige Claim-/Finish-Zyklen | 160 |
| Verstrichene Zeit | 0.733 s |
| Durchsatz | 218.4 Zyklen/s |
| Queueplan | Index Scan auf jobs_queue, keine Full-Table-Scan-Queueabfrage |

Der Test prüft eindeutige IDs, Historie/Terminalzustand und dass der alte Job trotz
niedriger Priorität zuerst drankommt. Das aktive Queuefenster bleibt gegenüber
abgeschlossenen Zeilen klein. Neue Laufzeitindizes ergänzen den bestehenden Queueindex;
der tatsächliche PostgreSQL-Planner hat hier jobs_queue gewählt. EXPLAIN ANALYZE mit
BUFFERS und vollständige Rohmessung stehen lokal in
.runtime/test-reports/phase-07-performance.json (ignoriertes technisches Testartefakt).

Reproduzieren: `CVE_DOCKER_SUDO=1 make jobs-concurrency-test` oder
`CVE_DOCKER_SUDO=1 make automation-integration`. Testgrenze unter 30 s prüft grobe
Regressionen; gemessene Zahlen hängen von Host und paralleler Last ab. Größere
Last-/Retention-/SLA-Untersuchungen gehören zur Betriebs- und Performancephase 23.
