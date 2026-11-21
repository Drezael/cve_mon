# ADR-0032: Inventarverarbeitung und Annahmekompatibilität

Status: angenommen für Phase 14, 07.11.2026.

Die Umsetzung aktiviert den vorgesehenen Dienst cve-inventory und verwendet vorhandene
Snapshot-/Kindtabellen und die Phase-7-Jobinfrastruktur. Die Annahme bleibt unveränderlich.
Ein Datenbanktrigger koppelt neue Annahme und Jobanlage; begrenzter Backfill übernimmt alte
Annahmen. Fachzustände stehen separat, damit der geschlossene Phase-13-Receiptvertrag
unverändert weiter funktioniert. Fachstatus wird zunächst nur intern/operatorseitig angeboten.

Snapshotidempotenz richtet sich global nach inventory_id, nicht nach Uploadquelle oder
Receipt. Verschiedene Quellen behalten ihre eigenen unveränderlichen Provenienzen und
werden mit einem regulären Snapshot verknüpft. Native Versiegelung und deferred Constraints
schützen Objektanzahlen und Fachabschluss. Administrative Tabellen erhalten keine Schreibrechte.

Current-Pointer getrennt von Serverstammdaten; deterministisches Maximum aus Erfassungszeit
und Inventar-ID unter Serversperre. Erfassungen nach dem serverseitigen Annahmezeitpunkt
bleiben mit Anomaliecode historisch. Partielle, fehlgeschlagene und während Archivierung
verarbeitete Daten dürfen keinen aktuellen vollständigen Bestand vortäuschen.

Ein technischer Replay verwendet die bestehende administrative Jobfunktion, niemals
Snapshotüberschreiben. Neue fachliche Normalisierung erfolgreicher Snapshots wird ohne
eigenen versionierten Fachvertrag nicht freigegeben. Keine Retention und keine automatische
Matching- oder Finding-Aktivierung. Die ursprünglichen Phasenkonzepte bleiben unverändert.
