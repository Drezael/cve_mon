# Docker Compose — Phase 2

Voraussetzungen: Linux, Docker/Compose mit Zugriff auf den Daemon, Python 3.12/.venv,
OpenSSL, Git und Make. Lokal geprüft: Engine 29.9.2, Compose v5.7.0. Benötigte Compose-Funktionen:
config --format json, up --wait und Bind-Mount create_host_path=false (moderne Compose V2).
Noch keine PostgreSQL-/Envoy-/n8n-/Postfix-/Python-Backendcontainer.

```bash
make setup
make compose-check
make dev-certs
CVE_DOCKER_SUDO=1 make nginx-check
CVE_DOCKER_SUDO=1 make infra-up
```

CVE_DOCKER_SUDO=1 nur bei ausdrücklich eingerichtetem passwortlosem sudo für Docker setzen.
Ohne diese Wahl verwenden die Skripte den normalen Docker-Zugang. Kein automatisches sudo
für Python-Setup, Zertifikate oder Hoständerungen. In dieser Sitzung wurde sudo vom Nutzer freigegeben.
Bereits vorhandene Entwicklungszertifikate werden nicht ersetzt; make dev-certs dann auslassen.

Konfiguration aus .env oder ersatzweise .env.example. Vorhandene .env niemals ungeprüft überschreiben.
Andere Datei: CVE_ENV_FILE=/pfad/zur/datei vor den Make-Befehl setzen oder manage.py --env-file verwenden.
CLI-Befehle können aus der Projektwurzel ausgeführt werden; die Shellwrapper ermitteln sie selbst.

```bash
CVE_DOCKER_SUDO=1 make infra-reload
CVE_DOCKER_SUDO=1 make infra-down
```

Nur der gewählte Compose-Projektname wird verwaltet; keine Prune-/Volumelösch-/Host-Firewallbefehle.
Base compose.yml definiert Nginx und fünf Netze, infrastructure/compose/development.yml ändert ausschließlich
Entwicklungsverhalten. Ports stehen einmal in der Basis; kein additiver öffentlicher Override.
Beim alleinigen Nginx-Start erzeugt Compose nur die beiden von Nginx benutzten Netze.
Ab Phase 3 verwendet PostgreSQL ausschließlich cve_data ohne Hostport; db-up startet diesen
Dienst separat. [PostgreSQL-Betrieb](postgresql.md).
Der config-only Audit-Override in tests/infrastructure/fixtures darf niemals gestartet werden.
Er hält die drei noch ungenutzten Definitionen zur echten Compose-Auflösung im Prüfmodell.

Direkte Auflösung ohne Daemon:

```bash
docker compose --env-file configuration/examples/development.env -f compose.yml -f infrastructure/compose/development.yml config
```

Vor manuellem docker compose up zuerst Konfiguration und minimales TLS-Bundle mit den
Werkzeugen rendern/prüfen. Nginx läuft als konfigurierter Nicht-Root-Benutzer; UID muss
zum rendernden Hostbenutzer passen. Keine globale container_name-/Netzwerkbenennung.
[Umgebungen](environments.md), [TLS](tls-certificates.md), [Wartung](maintenance.md).
