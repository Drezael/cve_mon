# Inventory Processor – Phase 14

`cve-inventory` 0.14.0 verarbeitet ausschließlich persistierte Submissions 1.0 und 1.1.
Der Dienst verwendet cve-common 0.7.0, dessen Registry, Worker, Heartbeat, Lease,
Fencing, Retry und Outbox. PostgreSQL bleibt Datenbank und Queue. Kein Zielserverzugriff.

Die API-Annahme legt über einen Datenbanktrigger in derselben Transaktion einen Job
`inventory.process_submission` mit einzigem Argument `submission_id` an. Originalbytes,
JSONB, beide Hashes, Identitäten und `accepted` bleiben unverändert. Separate
`submission_processing`-Zeilen referenzieren Job und Ergebnis. Der Worker holt beim
Start und anschließend pro Poll maximal 100 fehlende Zuordnungen nach. Eindeutige
Submission-PKs und eine gesperrte Zuordnungszeile verhindern konkurrierende Doppelanlage.
Ein vorhandener fehlgeschlagener Job wird nicht automatisch durch Backfill ersetzt.

Nach Claim wird ein begonnenes Verarbeitungsvorkommnis unter Prüfung der Job-Fence
festgehalten. Die Normalisierung läuft in einem kurzlebigen Spawn-Prozess mit 512 MiB
Adressraum, 30 CPU-Sekunden, 35 Sekunden Walltime und ohne Core-Dumps. Schema, Raw-SHA,
kanonischer SHA, JSONB, Server-/Inventaridentität, Schema und Erfassungszeit müssen zu den
persistierten Annahmemetadaten passen. Die identischen geschlossenen Vertragsschemas
werden im Wheel mitgeliefert und auf Bytegleichheit getestet. API-Validierung und
Processor verwenden denselben Eingangsvertrag; der Processor besitzt eigene Prüfungen
gegen den persistenten Datensatz. Widerrufene Zugangsdaten entwerten die vorher
verifizierte historische Annahme nicht. Es werden keine Tokenverifier geladen.

Eine zweite, gefencete Fachtransaktion sperrt die globale Inventaridentität. Sie schreibt
Snapshot, OS, Kernel/Hardware, Pakete, Dienste, Container, Images und Bereichsergebnisse
in Batches von höchstens 500 Zeilen. Anschließend versiegelt sie den Snapshot, aktualisiert
gegebenenfalls den Current-Pointer und schreibt Abschlussereignisse und Audit. Jobabschluss
und Fachcommit verwenden `ExecutionContext.complete`; eine verlorene Lease rollt alles zurück.
Ein zweiter Annahmekontext desselben Inventars erhält denselben fachlichen Snapshot,
behält aber seine eigene Submission und Herkunft.

Normalisierung `inventory-1` erhält Originalversionen und Originaldatensätze. Debian:
optional numerische Epoch, dann Teilung an der letzten Revisionstrennstelle. RPM:
Epoch-Version-Release einschließlich `~`, `^`, `+`, Distributionsrelease und Architektur.
Explizite Epoch-/Releasefelder müssen konsistent sein. Nicht strukturell normalisierbare
Versionen bleiben mit `invalid_version` erhalten, unbekannte Ökosysteme mit `unknown`.
Es findet kein Versionsvergleich statt. Identische Paketdatensätze werden dedupliziert;
unterschiedliche Versionen, Architekturen oder Quellpaketinformationen bleiben getrennt.
Quellpaketname und -version werden relational und im Originalobjekt erhalten.

Distributionskennungen entstehen nur aus der festen Zuordnung im Code; Originalname,
Release, Codename, Plattform und Architektur bleiben in `original_data`. Der laufende
Kernel steht separat von installierten Kernelpaketen. Hardwarefelder kommen ausschließlich
aus dem Vertrag. Dienste behalten Manager, Zustand, Aktivierungsstatus und Originaldaten.
Containerinstanzen behalten ihren erfassten Zustand und die Image-ID. Auflösung eines
Images erfolgt ausschließlich über die im selben Inventar vorhandene Image-ID; fehlende
Auflösung erzeugt einen Qualitätscode. Image-Referenzen und Digests bleiben unverändert;
Repository, expliziter Tag und Digest stehen zusätzlich strukturell getrennt in reference_parts;
es wird kein latest-Tag oder Registryname ergänzt. Mehrere Datensätze derselben Image-ID
vereinigen Referenzmengen und bewahren alle
unterschiedlichen Originaldatensätze. Ungültige Digestformen werden ausdrücklich markiert.
Tags werden nicht als stabile Imageidentität verwendet.

`complete`, `partial`, `failed`, Bereichsstatus und feste Diagnosecodes bleiben erhalten.
Fehlende optionale 1.0-Bereiche werden als `not_collected` geführt. `not_installed` bedeutet
nicht anwendbar, `unreachable` bedeutet fehlgeschlagen; beides ist in der Qualität erkennbar.
Ein erfolgreich verarbeitetes JSON ist kein Beweis für vollständige Erfassung.

[Snapshots](../database/inventory-snapshots.md),
[Auswahl](../database/inventory-current-selection.md),
[Betrieb](../operations/inventory-processor.md),
[Isolation](../security/inventory-processing-isolation.md).
