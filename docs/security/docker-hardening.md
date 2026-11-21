# Containerhärtung Phase 23

Compose definiert read-only Rootdateisysteme, cap_drop ALL, no-new-privileges, Limits für RAM/CPU/PIDs/nofile und begrenzte noexec/nosuid-tmpfs. PostgreSQL benötigt beim Start CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID; Postfix benötigt zusätzlich KILL für seine kontrollierten Dienstprozesse. Diese Ausnahmen bleiben eng und durch vorhandene Tests geprüft.

Phase 23 prüft nun für sämtliche Dienste exakt den freigegebenen Security-Opt-Satz und verbietet Geräte sowie Host-PID/IPC/UTS/Cgroup-Namespaces. seccomp=unconfined und apparmor=unconfined sind keine zulässige Problemlösung. Docker builtin Seccomp und docker-default AppArmor bleiben aktiv. Kein erzwungener User-Namespace-Wechsel ohne Migrations-/Kompatibilitätsnachweis.

Schreibpfade bleiben die bestehenden PostgreSQL-/Mail-/n8n-Daten, begrenzte tmpfs und die beiden minimierten Statusadapterverzeichnisse. API-Statusdaten werden read-only eingebunden. Kein Socket-, Hostroot- oder zusätzlicher Privilegienmount. Tests: tests/infrastructure und tests/hardening/test_controls.py; unveränderte Fachfunktion zusätzlich Pipeline-/Recoveryprüfungen.
