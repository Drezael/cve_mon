# FIRST EPSS – separater Tagesdatenstrom

Offizielle Grundlage: [FIRST Get the Data](https://www.first.org/epss/data).
Verwendeter Bulk-Endpunkt: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
beziehungsweise epss_scores-YYYY-MM-DD.csv.gz auf demselben Host. Die API ist kein Bulk-Ersatz.

Erste Zeile: #model_version:vYYYY.MM.DD,score_date:<ISO-Datum/Zeit>. Danach exakt
cve,epss,percentile. Der Enricher erhält Modellversion und Bewertungsdatum, prüft CVE-IDs,
Eindeutigkeit, Dezimalwerte zwischen 0 und 1 einschließlich sowie den Dateirahmen.
Score bedeutet prognostizierte Ausnutzungswahrscheinlichkeit in den nächsten 30 Tagen;
Percentile ist die relative Position in der Population und bleibt ein getrenntes Feld.

Mindestens 100.000 Zeilen im normalen Profil; Tests verwenden ausdrücklich eigene kleine
Profile. Gegenüber dem gültigen Vorgänger gilt zusätzlich eine Mindestquote von 90 Prozent.
Vollständigkeit bedeutet korrekter HTTP-Abschluss, Größenlimits, vollständiger Gzip-CRC/EOF,
CSV/Metadaten und Zeilenvalidierung. FIRST liefert in diesem Format keine vorausgesetzte
Sollzeilenzahl; die Anwendung erfindet keine solche Metadatenangabe.

Abgeschlossene Datenstände sind unveränderlich. Gleiche Datei/Datum/Modell erzeugt keinen
Doppelstand. Korrigierte Dateien desselben Tages erhalten eine eigene Datasetidentität mit
Original-SHA. Ältere nachimportierte Tage ersetzen den Current-Pointer nicht. Ein Fehler
lässt den letzten gültigen Stand unverändert. Fehlende CVEs ergeben keine Nullbewertung.
Der Read-View zeigt Datum, Modell, Alter und is_stale nach der versionierten Zwei-Tage-Regel.
Modellwechsel dürfen nicht als alleinige Änderung der Bedrohungslage interpretiert werden.
Ein Tagesstand erzeugt ein einziges Metadatensignal und keine CVE-/Matching-Massenjobs.
