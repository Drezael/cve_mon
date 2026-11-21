# EPSS-Dataset-Historie

cve.epss_import_runs speichert Dateiidentität (Datum, Modell, Original-SHA), URL, Status,
Zeilenzahl und Importzeit. cve.epss_daily_scores speichert CVE, Datum, Modell und NUMERIC(20,18)
für Score und Percentile mit Dataset-FK. Primärschlüssel (dataset_id,cve_id) verhindert Duplikate.
cve.epss_current_dataset ist ein Singleton-Pointer auf einen vollständig validierten Stand.

Native Constraints prüfen Wertebereiche, CVE-IDs, Dataset-/Datums-/Modellbindung, vollständige
Zeilenzahl und monotonen Current-Tag. Abgeschlossene Dataset-Metadaten und Scores sind
unveränderlich; neue Scores dürfen nur in offene Stagingstände geschrieben werden.
Gleiche Dateien werden wiederverwendet. Korrekturen eines Tages bleiben als weitere
Datasetrevision erhalten. Ältere Tagesimporte sind historische Daten, keine Current-Regression.

current_epss_scores liefert den aktuellen Stand mit Datum, Modell, Alter und Zwei-Tage-
Stale-Kennzeichnung. Fehlende Zeilen werden nicht als 0 interpretiert. EPSS besitzt absichtlich
keinen FK-Zwang zu bereits importierten CVERecords: eine vollständige Tagesdatei darf CVEs
enthalten, die noch kein Enrichment besitzen. Dadurch entsteht keine automatische CVE-Massenanlage.

Auch der EPSS-Pointer besitzt einen monotonen Publikationszähler. Eine legitime erneute
Veröffentlichung eines bekannten Tagesstands erzeugt ein neues Signal ohne neue Doppelwerte.
