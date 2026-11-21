# ADR-0030: Lokale Ansible-Erfassung und gemeinsamer Vertrag 1.1

Aktueller Stand: Die frühere externe Ansible-Anbindung ist durch die
repository-eigenen Playbooks und Werkzeuge ersetzt; siehe
[ADR-0038](ADR-0038-external-configuration.md) und
[Ansible-Anleitung](../../../integrations/ansible/README.md).
Der folgende Text dokumentiert die historische Entscheidung.

Status: accepted. Datum: 07.11.2026.

Phase 12 wird im vorhandenen Drezael/ansible-Repository implementiert, lokal unter
/home/gerald/Documents/GitHub/ansible. Bestehender Launcher und dessen Metadaten, Verzeichnisse,
Host-Specs, Vault-/SSH-/sudo-Tasks bleiben die Grundlage. Keine zusätzliche Rolle, Collection,
Agenten oder neue Kryptografie. Controller-Python normalisiert, validiert und speichert,
führt aber keine Remoteoperationen aus. Keine Uploads oder Phase-14-Fachfunktionen.

Das unveränderliche Format 1.0 kann mehrere ausdrücklich geforderte Phase-12-Daten nicht
abbilden: Hardware, OS-Familie/Kernelversion, RPM-Einzelfelder, Service-Manager, Docker-
Image-ID und separate lokale Images. Weglassen wäre Datenverlust; unversionierte Zusatzfelder
würden den geschlossenen Vertrag verletzen. Deshalb ergänzt ein gemeinsames, ebenfalls
geschlossenes Schema 1.1 diese Felder. Originalschema 1.0 und Beispiele bleiben bytegleich.
Beide Versionen haben dieselbe Server-/Inventaridentität, Statuslogik und Datenhoheitsgrenze.
Die neuen Pflichtbereiche dokumentieren auch nicht installiertes oder fehlerhaftes Docker.

Ansible erhält bytegleiche Vertragskopien. API 0.11.1 wählt explizit nach Version den
Validator, unterstützt weiter 1.0 und lehnt unbekannte Versionen ab. Additive Revision 00018
erweitert ausschließlich den erlaubten Versionswert der Annahmen; bestehende Originaldaten
und Privilegien bleiben unverändert. Neue OpenAPI-Varianten dokumentieren beide Formate.
Beide Uploadwege testen Speicherung von 1.1 einschließlich Originalbytes und Provenienz.
Die Begrenzungen, Unveränderlichkeit, Authentifizierung und 202/accepted bleiben bestehen.

Die Host-Spec erhält den kontrollierten Schlüssel server_uuid aus vorheriger Registrierung.
Keine automatische Zuweisung oder API-Suche. Eine neue inventory_id bezeichnet ausschließlich
einen Erfassungslauf. Mehrfachauswahl ist explizit, UUID-Konflikte werden vor SSH abgelehnt.
Einzelne Hostfehler verwerfen keine Ergebnisse anderer Hosts. Controller-UTC trennt lokale
Erfassungszeit von der Zielhostzeit. Alle Dateipfade sind privat, ohne Symlinks und atomar
gegen Überschreiben geschützt. --check validiert ohne lokale Veröffentlichung.

[Vertrag 1.1](../../../contracts/inventory/inventory-v1.1.schema.json),
[Phase-12-Übergabe](../../development/phase-12-handover.md).
