# Matching Worker betreiben

Voraussetzung: Migration 00023 und eigene DB-Credentials aus der bestehenden Provisionierung.
Kein automatischer Datenimport oder Backfill beim Start. In Entwicklung:

```sh
CVE_DOCKER_SUDO=1 make matching-build
CVE_DOCKER_SUDO=1 make matching-up
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.cve_matcher.manage metrics
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.cve_matcher.manage enqueue --kind reconcile
```

Der letzte Befehl ist ein ausdrücklicher Backfill-Auftrag und gehört nicht zur Startsequenz.
Er indexiert aktuelle Enrichment-Revisionen, danach aktuelle Snapshots, jeweils 100 Inputs
pro Fortsetzungsjob. Snapshot-/CVE-Ereignisse erzeugen gezielte Jobs. Childjobs enthalten
nur IDs und Regelversionen. Grenzen: Quelldokument/Paketbasis jeweils 32 MiB, Paketanzahl
100000, Containeranzahl 10000. Zusätzlich höchstens 4096 Affected-Aussagen, 16384 Komponentenentscheidungen und 32 MiB serialisiertes Resultat pro Bewertung; Überschreitung erzeugt einen terminalen Payloadfehler statt eines Teilcommits. Zusätzlich höchstens 4096 Affected-Aussagen, 16384 Komponentenentscheidungen und 32 MiB serialisiertes Resultat pro Bewertung; Überschreitung erzeugt einen terminalen Payloadfehler statt eines Teilcommits. Worker verwendet maximal vier parallele Tasks mit Pool-
Headroom, Jobbudget 3600 Sekunden und drei Versuchen. Produktionswerte bleiben konfiguriert.

Interne /health/live, /health/ready und /metrics. Metriken zeigen Jobs, Altersgrenzen,
Kandidaten, Statusverteilung, Konflikte, unsichere Bereiche, Abdeckung, veraltete Resultate,
Publikationen, Laufzeiten und tatsächlich eingerichtete Outbox-Zustellungen. Keine
öffentliche Steuerungs-API. Dispatcher-Ziele bleiben bis Phase 18 ausdrücklich geschlossen.
