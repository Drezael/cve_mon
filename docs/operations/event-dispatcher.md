# Event Dispatcher bereitstellen

```bash
make setup python-check
CVE_DOCKER_SUDO=1 make db-up db-provision db-migrate
CVE_DOCKER_SUDO=1 make dispatcher-build dispatcher-prepare dispatcher-up
CVE_DOCKER_SUDO=1 make api-up api-smoke-test
CVE_DOCKER_SUDO=1 make dispatcher-test
```

Python 3.12, gemeinsame/API-/Dispatcherpakete 0.7.0, unveränderter gesperrter externer
Runtime-Graph. Build verwendet geprüfte Wheels/Hashes und Netzwerk-none-Installation,
keine Secrets oder Repository-Gesamtkopie. Bootstrap installiert alle drei Pakete.
Image cve-event-dispatcher:0.7.0-phase07, API-Kompatibilitätsimage cve-api:0.7.0-phase07.

`.runtime/automation/<projekt>`: eigenes event_dispatcher.password, ca.crt (PostgreSQL-CA)
und targets.json; Verzeichnis 0700, Secret/Registry 0600. Nur dieser readonly-Mount.
Entwicklung legt eine leere Registry an, Produktion braucht externe PKI/Credentials.
Keine anderen Runtime-Rollen/Migrations-/SMTP-Secrets im Container.

Ziel freigeben: zuerst ausdrücklich autorisierte DB-Target-/Eventroute konfigurieren,
passende private HTTPS-/Token-/CA-Dateien bereitstellen und targets.json gemäß Target-
Modell schreiben, Dispatcher neu erstellen. Standard bleibt ohne Zustellziele. Keine
produktiven n8n-Workflows. Tests verwenden einen isolierten HTTPS-Empfänger.

Konfiguration über DISPATCHER_CONCURRENCY/LEASE_SECONDS/HEARTBEAT_SECONDS/POLL_SECONDS/
SHUTDOWN_SECONDS in .env.example; [genaue Grenzen](../deployment/environments.md).
In-App-Präfix CVE_DISPATCHER_, Poolgröße standardmäßig 3, ein Uvicorn-Prozess, interner
Port 8000, RAM 256 MiB/CPU 1/PIDs 64/FDs 1024/Temp 8 MiB. Kein Hot Reload.

/health/live prüft den Prozess, /health/ready DB plus tatsächlichen lebenden Loop und
frischen Tick; DB-Ausfall führt zu 503, keine schreibende Healthoperation. /metrics
zeigt ausschließlich Aggregate. SIGTERM stoppt neue Claims und drainiert begrenzt;
SIGKILL wird über persistente Leases wiederhergestellt. Nach manuellem Docker-kill
explizit wieder starten, da Docker manuelle Stopps nicht zwingend automatisch neu startet.

Fehlerdiagnose: Schema-Head, private Dateirechte/UID, CA/Hostname, Authentifizierung,
Ziel-ID und Aktivierung, Retries/Leases, Queuealter. Nie Token, komplette URLs mit
Credentials, Payloads oder Exceptions protokollieren. Eigene Projektlabels vor Betrieb prüfen.
