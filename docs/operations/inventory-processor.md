# Inventory Processor betreiben

Voraussetzung: vorhandene PostgreSQL-Installation, Rollen und TLS aus Phase 3 sowie
Revision `00019_inventory_processing`. Keine automatischen Server, Benutzer oder Tokens.

```bash
make inventory-processor-check
CVE_DOCKER_SUDO=1 make inventory-processor-integration
CVE_DOCKER_SUDO=1 make inventory-processor-build
CVE_DOCKER_SUDO=1 make db-migrate
CVE_DOCKER_SUDO=1 make inventory-processor-up
```

Passwortloses sudo wird nur für die explizite Docker-CLI benutzt. Ohne diese Umgebung
verwendet der Helfer den normalen Dockerzugang. Befehle sind auf das gewählte Composeprojekt
beschränkt. In Produktion müssen Passwort und PostgreSQL-CA unter
`.runtime/inventory-processor/<projekt>/` extern bereitgestellt werden. Der Helfer erzeugt
keine Produktionscredentials. Entwicklung kopiert nur die bestehende getrennte
`inventory_processor.password` und die Datenbank-CA in ein privates Dienstverzeichnis.

Standardparallelität 1, konfigurierbar über `INVENTORY_PROCESSOR_CONCURRENCY` auf höchstens 2
pro Instanz. Mehr Instanzen verwenden dasselbe persistente Claim-/Fence-Verfahren.
Jobtyp: 120 Sekunden maximale Laufzeit, höchstens 3 Versuche; Basis-Retry mit Jitter aus
Phase 7. Lease 15 Sekunden, Heartbeat 3 Sekunden, Pool begrenzt. Normalisierung:
512 MiB AS, 30 CPU-/35 Wallsekunden. Container: 1536 MiB, eine CPU, 64 Prozesse.
Der Wheel-Bau verwendet frische temporäre Quellkopien, damit keine veralteten
Setuptools-Buildcaches übernommen werden. Das tatsächliche Containerimage wird in der
Integration gegen den Quellcode und die gepackten Eingangsverträge geprüft.
Batches: 500 Zeilen. Normaler Fachcommit enthält alle Tabellen und den gefenceten Jobabschluss.

Interne Endpunkte: `/health/live`, `/health/ready`, `/metrics` auf Port 8000 ohne Hostport.
Live meldet Prozessleben; ready erfordert laufenden gesunden Worker und geprüfte Datenbank.
Metriken: Annahmen, ausstehend, erfolgreich/fehlgeschlagen, Retries, summierte
Verarbeitungsdauer, Pakete/Container, aktive Worker, älteste wartende Annahme,
Current-Pointer-Änderungen und Datenbankfehler. Identitätswerte sind keine Metriklabels.

Metadaten abfragen, ohne Originalpayload oder Secrets auszugeben:

```bash
.venv/bin/python -m scripts.inventory_processor.manage metrics
.venv/bin/python -m scripts.inventory_processor.manage submission --id <submission-uuid>
.venv/bin/python -m scripts.inventory_processor.manage snapshot --id <snapshot-uuid>
.venv/bin/python -m scripts.inventory_processor.manage history --id <server-uuid>
.venv/bin/python -m scripts.inventory_processor.manage current
.venv/bin/python -m scripts.inventory_processor.manage permissions
.venv/bin/python -m scripts.inventory_processor.manage verify
```

Historienausgaben sind auf 100 Einträge begrenzt. Fehlende Zuordnungen werden automatisch
nachgeholt; einmalig lässt sich `... manage backfill` aufrufen (höchstens 100 pro Aufruf).
Wiederholte Aufrufe verändern bestehende Zuordnungen nicht. Quoten für bewahrte Rohdaten
werden durch Verarbeitung nicht freigegeben. Keine automatische Retention oder Löschung.

Die bestehenden POST-202-Receipts und Status-GETs bleiben kompatible Annahmenachweise mit
`accepted`; der Phase-13-Client muss nicht geändert werden. Fachzustände liefert die
separate interne Datenbankview bzw. der Operatorbefehl `submission`. Ein zukünftiger
öffentlicher Fachstatus benötigt einen eigenen ausdrücklich versionierten API-Vertrag.

[Recovery](inventory-recovery.md), [Neuverarbeitung](inventory-reprocessing.md),
[Abnahme](../development/phase-14-acceptance.md).
