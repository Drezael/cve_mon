# Auswahl des aktuellen Inventars

Die technische Tabelle `inventory.server_current_snapshots` enthält genau einen Zeiger
je Server. Der Processor erhält keine direkten Schreibrechte darauf. Die begrenzte
SECURITY-DEFINER-Funktion `inventory.select_current` prüft Aufrufer, persistierten
verarbeiteten Snapshot, vollständige Erfassung, Eignung und aktiven Server.

Die Auswahl verwendet eine gemeinsame Sicherheitsmutation-Sperre und danach eine
Advisory-Sperre pro Server. Maßgeblich ist das Maximum aus `(captured_at, inventory_id)`.
Gleiche Erfassungszeiten werden deterministisch durch die globale UUID entschieden;
Annahme- und Verarbeitungsreihenfolge bestimmen den Sieger nicht. Ältere vollständige,
neuere partielle und fehlgeschlagene Erfassungen bleiben in der Historie.

Die API erlaubt bis zu fünf Minuten Uhrabweichung. Ein bei Annahme tatsächlich in der
Zukunft liegendes Inventar wird vom Processor mit `future_collection` historisiert und
nicht zum aktuellen Bestand. Es wird später nicht automatisch aktuell. Mehr als 30 Tage
alte Erfassungen erhalten `stale_collection`; sie dürfen einen neueren aktuellen Bestand
niemals verdrängen. Ein Server mit ausschließlich partiellen Inventaren hat keinen
vollständigen Current-Pointer. Fehlgeschlagene oder nicht erreichbare Docker-Erfassung
wird nicht als vollständiger leerer Dockerbestand interpretiert.

Vor Archivierung angenommene Daten dürfen historisch verarbeitet werden. Ein archivierter
Server erhält dabei keinen neuen Current-Pointer und wird nicht reaktiviert. Vorhandene
historische Zeiger bleiben erhalten; Verbraucher müssen zusätzlich den administrativen
Archivierungsstatus beachten. Eine spätere Reaktivierung löst keine automatische Auswahl
historischer Daten aus. Administrative Stammdaten, Gruppen und ACLs bleiben unverändert.

Die vorhandene View `current_snapshots` respektiert für neue Snapshots den Pointer.
Legacy-Snapshots behalten ihr bisheriges Auswahlverhalten, solange kein verifizierter
Phase-14-Pointer existiert. Sobald dieser existiert, ist ausschließlich er maßgeblich;
auch ein alter unvalidierter Zukunftszeitstempel darf die View nicht verdrängen. Bereichsviews
`effective_sections` und `positive_partial_sections` bleiben positive Bereichsnachweise;
sie sind kein Ersatz für den vollständigen Matchingbestand.
