# Performanceergebnisse Phase 23

Tatsächlich gemessene lokale Stufen mit gleicher synthetischer Arbeitskette und unveränderten Sicherheitsgrenzen.

| zusätzliche Server | Pakete | API p95 vorher/nachher (ms) | Fehler vorher/nachher | Annahme nachher (ms) | Processor nachher (ms) | Matching nachher (ms) | Findings nachher (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 100 | 4186.2 / 237.5 | 6 / 0 | 668.4 | 736.9 | 701.8 | 104.6 |
| 1000 | 1000 | 4213.8 / 215.3 | 6 / 0 | 723.0 | 1089.5 | 695.7 | 131.9 |
| 10000 | 10000 | 4106.8 / 200.8 | 24 / 0 | 1909.3 | 5065.5 | 2835.3 | 161.2 |

Rohproben, p50/p95/p99, Querypläne, Queuezustände, Verbindungen, PostgreSQL-CPU/RAM/Block-I/O sowie Prozess-Spitzen-RSS stehen in phase-23-performance-before.json und phase-23-performance-after.json. Je Stufe 24 API-Proben und höchstens vier parallele Aufrufe. Die Baseline enthält 36 tatsächliche HTTP-503-Fehler; nachher bestehen alle Paket-, Matching- und Findingnachweise bei null API-Fehlern. Lokale Stichproben sind keine Produktions-SLO oder statistisch belastbare p99-Zusage. JIT bleibt ausschließlich im API-Sicherheitskontext deaktiviert.
