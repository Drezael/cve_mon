# Unveränderliche Inventarsnapshots

Revision `00019_inventory_processing` erweitert die vorhandenen Tabellen additiv.
Die ersten 18 Migrationen bleiben unverändert. Legacy-Snapshots ohne `submission_id`
bleiben referenzierbar; ihre bisherigen Status-/Bereichsregeln gelten weiter. Eine kollidierende
Inventar-ID wird als existing_inventory_conflict abgelehnt und nicht unbemerkt mit einer
neuen Submission verbunden. Ein nativer Binding-Trigger prüft zusätzlich Server, Inventar-ID,
Original-JSON und verarbeiteten Zustand bei jeder erfolgreichen Zuordnung.

`inventory.snapshots` enthält eigene UUID, globale eindeutige Inventar-ID, Server,
Originalsubmission, Originalbytes/JSON/SHA-256, Zeitpunkte, Schema, Qualität,
Normalisierungs- und Processorversion sowie Objektanzahlen. Herkunft und kanonischer
Hash sind über die unveränderliche Submission referenziert. Weitere Submissions desselben
Inventars referenzieren denselben Snapshot über `submission_processing`; damit gehen
abweichende Uploadwege und Identitäten nicht verloren.

Vorhandene `operating_systems`, `packages`, `services`, `containers` und
`collection_sections` werden verwendet; `kernels`, `images` und
`server_current_snapshots` ergänzt. Paket-Originalversion steht weiterhin in `version`.
Epoch, Upstream, Release und Normalisierungsstatus sind zusätzliche Felder. Ein Hash
über den gesamten Paketdatensatz erlaubt unterschiedliche Quellinformationen. Der
Legacy-Paketschlüssel gilt weiter für alte Datensätze ohne diesen Hash.

Snapshots werden innerhalb einer Transaktion zunächst `processing` angelegt und zuletzt
`processed`. Deferred Constraints erzwingen abgeschlossenen Zustand, Bereichsanzahl,
Kernelzeile, gespeicherte Objektanzahlen und erfolgreich zugeordnete Originalsubmission.
Kein solcher Zwischenzustand darf committen. Nach Versiegelung verhindern native Trigger
UPDATE/DELETE des Snapshots sowie INSERT/UPDATE/DELETE seiner Kinddatensätze, auch durch
den normalen Datenbankowner. Runtime-Rollen können weder Originale noch Historie löschen.

`inventory.processing_status` trennt Fach- und Jobstatus: accepted bei Queue/Retry,
processing bei laufendem Job, completed nach Fachcommit, rejected_after_acceptance bei
permanenter Vertragsabweichung, failed bei terminalem Jobfehler/Abbruch. Technische
Versuche und Fehler bleiben in der Phase-7-Historie. Rohsubmissionstatus und bestehende
HTTP-Receipts bleiben accepted und bedeuten weiterhin ausschließlich Annahme.

`inventory.matching_snapshots` ist der Metadatenvertrag für Phase 17. Pakete, OS,
Kernel und Dockerdaten können über `snapshot_id` mit festen Mengenabfragen gelesen
werden. Keine Vollpayloads in Outbox oder Betriebslogs. Keine automatische Retention.
Annahmekapazitäten zählen weiterhin alle bewahrten Originalbytes; Verarbeitung ist
keine Löschung und gibt diese Speicherquoten nicht automatisch frei.

Die bestehenden Annahmemetriken security.inventory_metrics zählen seit Revision 00019
nur noch tatsächlich wartende/laufende Submissions als pending. Bewahrte Originalbytes
und deren Speicherquoten bleiben davon getrennt; abgeschlossene Verarbeitung ist kein
Löschen oder automatisches Freigeben von Retentionskapazität.
