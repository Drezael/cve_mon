# Argon2id-Baseline Phase 8

Lokaler Python-3.12-Messlauf am 06.11.2026 während paralleler Integrationsprüfungen:

| Größe | Messung |
|---|---|
| Speicher / Iterationen / Parallelität | 19456 KiB / 2 / 1 |
| Gleichzeitig erlaubte KDFs | 2 |
| Median acht Verifikationen | 32.98 ms |
| Vier Verifikationen mit Semaphore | 126.97 ms |
| Prozess-RSS-Spitze | 81132 KiB |

Reproduzieren: `.venv/bin/python scripts/security/benchmark-passwords.py`.
Keine Konten, Klartextwerte oder DB-Verbindungen; zufällige Testwerte nur im Prozess.
Rohdaten lokal .runtime/test-reports/phase-08-argon-baseline.json. Das ist ein Host-
KDF-Basiswert, kein Produktions-SLA und keine vollständige HTTP-Lastmessung. API-Grenze
256 MiB, Standard-KDFs zusammen 38 MiB; ein Uvicorn-Prozess. Größere konfigurierte Kosten
benötigen eine eigene Hardwaremessung innerhalb des erzwungenen Ressourcenbudgets.
