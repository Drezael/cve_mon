# Phase-23-Performancematrix

| Szenario | Umfang | Nachweis |
|---|---|---|
| Kleine/mittlere/große Liste | 100/1000/10000 zusätzliche Server,4 parallele Requests | test_workload.py, vollständige Rohproben/p95/p99 |
| Inventar | 100/1000/10000 Pakete, echte Annahme/Processor | Anzahl in Snapshot und Quellhash erhalten |
| CVE/Enrichment/EPSS | bestehende1000-/10000-Zeilen-Fälle | phase-23-pipelines.xml |
| Matching/Findings | tatsächliche Arbeitskette und Backfill | phase-23-performance.json, Pipeline-/Versionsregression |
| Notification |100 berechtigte Empfänger | Pipelinefall performance_hundred_authorized_recipients; kein echter Versand |
| Queue |160 Claims/8Claimer,2250 historische Jobs | phase-23-workers.xml |
| Frontend | Produktionsbuild/Komponenten/TLS-Browser | phase-23-frontend.xml und bestehende minimierte Browserberichte |

Baselinefehler bleiben ausgewiesen. Kapazitätsversprechen und fiktive Laststufen sind unzulässig.
