# Kontrollierte Wiederverarbeitung

Normale Retries referenzieren dieselbe Submission und erzeugen keine zweite fachliche
Inventaridentität. Ein Receipt eines anderen Uploadwegs oder technischen Identitätskontexts
behält seine Herkunft, erhält aber denselben Snapshot derselben globalen Inventar-ID.

Für terminal fehlgeschlagene oder abgebrochene Jobs existiert der explizite administrative
Phase-7-Replay mit neuer Job-ID und `replay_of`, unveränderlicher Versuchshistorie und
Runtime-Audit. Beispiel nach Prüfung der Fehlerursache:

```bash
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.automation.manage replay --job-id <job-uuid>
```

Die Rolle api_security ist dafür schon in der vorhandenen Jobsteuerung erforderlich.
Backfill setzt terminale Jobs nicht zurück. Ein erfolgreich abgeschlossener Job ist nicht
replaybar. Ein persistierter Snapshot wird bei Wiederanlieferung oder explizitem technischem
Replay nicht verändert. Eine neue Normalisierungsrevision bestehender erfolgreicher
Inventare ist in Phase 14 absichtlich keine automatische Operatoroption: sie benötigt einen
neuen versionierten Fachvertrag, eigene Identität und Auditspur in einer späteren Migration.
Es darf insbesondere weder der Unique-Key entfernt noch der alte Snapshot überschrieben werden.

[Recovery](inventory-recovery.md), [Snapshotmodell](../database/inventory-snapshots.md).
