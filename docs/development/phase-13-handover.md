# Übergabe an Phase 14

Phase 13 ist im vorhandenen /home/gerald/Documents/GitHub/ansible implementiert.
Einstieg: playbooks/server.inventory.submit.yml über den vorhandenen Launcher. Betriebliche
Anleitung und vollständige Einzelabnahme unter docs/inventory_submit/ in dieser Arbeitskopie.

Erforderlich sind registrierte host_specs.server_uuid, vorhandene Exporte 1.0/1.1,
ausdrückliche Dateiauswahl, private feste Operatorconfig und administrativ bereitgestellte
mTLS-/Tokencredentials im vorhandenen Vaultverfahren. Kein automatischer Collect, keine
Zielserververbindung, kein automatisches Ausstellen von Credentials. Originale bleiben erhalten.

Phase 14 erhält unveränderte persistierte Submissions einschließlich serverseitiger
Provenienz, Schema, Hashes, Zeit und Erfassungsstatus. Lokale Receipts sind technische
Nachweise, keine Datenquelle für Autorisierung oder fachliche Snapshots. 202/accepted
bedeutet ausschließlich Annahme. Ein Status-GET ohne Payload-Hash bestätigt keine neuen
Dateibytes; fehlender lokaler Receipt wird nur nach bestätigt wiederholtem POST erzeugt.

Neue Verarbeitungszustände/Antwortfelder müssen ausdrücklich versioniert werden; der
aktuelle Client akzeptiert ausschließlich den geschlossenen bestehenden Annahmevertrag.
Kein Processor, Matching, Finding Management oder fachlicher Job vorgezogen. API 0.11.1,
Revision 00018 und vorhandene Inventarschemas unverändert. Die CI benötigt die dazu passende
Ansible-Revision über ANSIBLE_SUBMIT_REF; sie wurde nicht remote ausgeführt.
[Abnahme](phase-13-acceptance.md), [ADR-0031](../architecture/decisions/ADR-0031-ansible-submit-phase13.md).
