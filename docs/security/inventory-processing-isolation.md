# Isolation der Inventarverarbeitung

Der Container besitzt ausschließlich `inventory_processor`, private Passwortdatei und
PostgreSQL-CA. Keine interaktive Anmeldung, keine API-/mTLS-Uploadtokens, SSH-Schlüssel,
sudo-Dateien, Docker-Sockets oder externen API-Credentials. Nichtroot, read-only Rootfs,
cap_drop ALL, no-new-privileges, Prozess-/CPU-/RAM-Limits und begrenztes noexec-Tmpfs.
Nur das interne Netz cve_data, kein Hostport und kein Egress-Proxy.

Die Rolle liest ausschließlich die notwendigen persistierten Inventare und technischen
Job-/Ergebnisdaten. Alte fachfremde Schreibrechte auf Kindtabellen werden reduziert;
INSERT und die begrenzten Snapshotstatusfelder bleiben verfügbar. Nach Commit sperren
native Trigger jede Mutation versiegelter Bestandsdaten. API-Ingest kann keine Snapshots
mehr direkt erzeugen. Administrative Server-, Gruppen-, Sortier-, Benutzer-, Rollen-,
ACL-, Token- und Zertifikatstabellen erhalten keine zusätzlichen Schreibrechte.
Current-Pointer-Änderungen sind nur über die feste prüfende Datenbankfunktion möglich.

Payloadwerte werden parameterisiert gebunden. SQL-Identifier stammen aus festem Code.
Kein eval, Shellaufruf, SSH, Ansible, Docker oder HTTP im Verarbeitungspfad. Der lokale
Normalisierungsprozess erhält ausschließlich persistierte Daten. Identitäts-/Provenienz-
felder stammen aus der Annahme, nicht aus dem Payload. Historische Autorisierung wird
nicht mit späterem Widerruf verwechselt. Geheimnisse und JSON-Originale erscheinen weder
in Fehlercodes noch Outbox-/Auditmetadaten oder Logs.

Die vorhandene Logging-Redaktion bleibt aktiv. Jobfehler verwenden die endliche
Phase-7-Klassifikation; Normalisierungsfehler ausschließlich feste kurze Codes.
Terminale technische Jobfehler erzeugen einen Metadaten-Outboxeintrag innerhalb der
Jobstatus-Transaktion. Diese feste Datenbanktriggeroperation nutzt die vorhandene
Outbox und registrierte event_types und legt ggf. konfigurierte Zustellungen an.
Auslieferungsziele bleiben standardmäßig geschlossen; kein Matchinghandler wird aktiviert.

[Tests](../testing/phase-14-test-matrix.md), [Betrieb](../operations/inventory-processor.md).
