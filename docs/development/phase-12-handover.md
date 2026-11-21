# Phase-12-Übergabe

Implementierung und vollständige Betriebsdokumentation liegen im vorhandenen Ansible-
Repository /home/gerald/Documents/GitHub/ansible unter docs/inventory/.
Einstieg: playbooks/server.inventory.collect.yml über den unveränderten Python-Launcher.
Registrierte host_specs.server_uuid ist vorab erforderlich; bestehende Hostdateien wurden
nicht automatisch verändert. Standardausgabe: inventory_exports/<server_uuid>/<utc>-<inventory_uuid>.json,
0700/0600, atomar ohne Überschreiben, keine Symlinks. --check erzeugt keine Dateien.

Phase 13 wählt bereits validierte Dateien ausdrücklich aus und sendet vom Controller über
mTLS plus gebundenes Token an Phase 11. Collect löst niemals Submit aus und benötigt keine
API-Credentials. Retry erhält inventory_id und Originalbytes. HTTP 202 bleibt ausschließlich
persistente Annahme. Gültiges partial behält den Status, failed wird nicht veröffentlicht.

Gemeinsame Formate: 1.0 unverändert, 1.1 additiv für den vollständigen Erfassungsumfang.
API 0.11.1 und Revision 00018 unterstützen beide. Die Originalbytes bleiben unveränderlich;
Phase 14 muss die zusätzliche Version explizit interpretieren. Keine Processorjobs,
CVE-Auswertung, automatische Registrierung oder administrative Datenänderung implementiert.
[Vertrag](../../contracts/inventory/inventory-v1.1.schema.json),
[Abnahme](phase-12-acceptance.md), [ADR-0030](../architecture/decisions/ADR-0030-inventory-collection-phase12.md).
