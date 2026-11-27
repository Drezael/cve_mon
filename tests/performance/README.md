# Leistungsprüfungen

Ausführbare Leistungsprüfungen liegen bei ihren Fachbereichen, unter anderem in
`tests/automation/integration/test_performance.py`, den Inventory-, Matching- und
CVE-Suiten sowie `tests/hardening/test_workload.py`. Sie prüfen begrenzte
Arbeitsschritte, SQL-Pläne, Speicherbudgets und repräsentative Datenmengen.
`make qa-full` führt auch diese Pythonfälle aus. Gezielte Make-Ziele wie
`inventory-processor-performance` sind in der Makefile aufgeführt.

Ergebnisse gelten für den jeweiligen Testhost und die dokumentierte Datenmenge.
Voraussetzungen stehen in [Tests und QA](../../docs/testing/README.md).
