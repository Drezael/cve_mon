# Ist-Analyse T14.01.01 / T14.02.01

Vor Implementierung durch lesende Repositoryprüfung ermittelt: Arbeitskopie
`/home/gerald/Documents/cve_mon`, Branch main, weiterhin ohne initialen Commit.
Projektdateien sind unversioniert; Änderungen werden deshalb mit SHA-256-Ausgangsmanifest
abgegrenzt. Keine AGENTS.md im Projekt oder in den maßgeblichen Elternverzeichnissen.

Vorhanden: PostgreSQL 18 mit 18 linearen Alembic-Migrationen, sechs eigene Dienste,
API 0.11.1, cve-common/Dispatcher 0.7.0. cve-inventory enthält nur ein Planungs-README.
Annahme unterstützt 1.0/1.1, beide Uploadwege, Originalbytes/JSONB, beide Hashes,
unveränderliche Identitätsregistry, verifizierte Provenienz, Audit und Outbox. Kein
Annahme-Job, keine normalisierten Laufzeitbestände und kein gestarteter Inventory-Worker.
Die normale lokale Datenbank enthält keine fachlichen Submissions oder Snapshots.

Die Datenbank besitzt bereits snapshots, collection_sections, operating_systems,
packages, services und containers. Alte Snapshots haben mutable Processing-Metadaten;
Kindtabellen sind noch nicht versiegelt. Das ursprüngliche Snapshot-Schema erlaubt nur
1.0 und aktive Server. Paket-Eindeutigkeit ignoriert zusätzliche Quellmetadaten.
Current-Snapshots werden bisher über eine View bestimmt, ohne eigenen technischen Zeiger.
Die vorhandene Rolle inventory_processor besitzt teilweise zu breite Kindtabellenrechte,
aber noch keine Annahme-Payloadleserechte. Keine administrativen Schreibrechte.

Phase 7 liefert Registry, PostgreSQL-Claim SKIP LOCKED, persistente Leases und Versuche,
Heartbeat, Fencing, begrenzte Laufzeit/Retry, Recovery, Replay und Outbox. Diese Komponenten
werden wiederverwendet. Die geschlossenen Dispatcherziele bleiben unverändert.
Phase 12/13 liegen im separaten vorhandenen Ansible-Repository und benötigen für die
Verarbeitung keine Änderung. Der Submitclient akzeptiert ausschließlich den bestehenden
geschlossenen accepted-Receiptvertrag. Fachzustände dürfen diesen Vertrag nicht ersetzen.

Fehlend sind Handler, Jobbereitstellung/Backfill, begrenzte Revalidierung/Normalisierung,
versiegelte Fachtransaktion, Kernel-/Imagedaten, Herkunftsverknüpfung, Statushistorie,
Current-Pointer, Betriebsmetriken und deren spezifische Tests. Revision 00019 ergänzt diese
Teile additiv. Die ersten 18 Migrationen, Eingangsverträge und Ansible-Dateien bleiben erhalten.

Risiken und Entscheidungen: globales inventory_id statt Receipt für Snapshotidempotenz;
keine Wiederautorisierung historischer Annahme anhand inzwischen widerrufener Tokens;
keine Verdrängung durch partial/failed oder Zukunftszeit; keine Änderung administrativer
Serverdaten; keine Kinddatensätze nach Snapshotversiegelung; Fachcommit nur mit gültiger
Job-Fence; keine Rückgabe sensitiver Validatorfehler; begrenzter Prozess/Batches/Pool.
Kein neues CVE-Matching, keine zusätzliche Queue, keine Zielserververbindung.

Die Analyse erfolgte vor Code-/Migrationsänderungen. Die anschließend vom Nutzer beauftragte
vollständige Phase setzt alle Folgeaufträge fort; die im Phasendokument enthaltene einzelne
Analyse-Promptvorlage begrenzt diesen umfassenderen Implementierungsauftrag nicht.
