# EPSS synchronisieren

```sh
.venv/bin/python -m scripts.cve_enricher.manage enqueue --kind cve.epss.sync_daily
.venv/bin/python -m scripts.cve_enricher.manage enqueue --kind cve.epss.sync_daily --date 2026-11-07
.venv/bin/python -m scripts.cve_enricher.manage epss
```

Im laufenden Dienst steuert n8n den Import über die persistente `cve.refresh`-Queue.
Der Dashboard-Button legt denselben zentralen Aktualisierungsauftrag an wie bei V5 und
KEV. Die obigen Operatorbefehle sind für gezielte Diagnose und historische Importe;
auch ihre Aufträge benötigen bei aktivierter Zentralsteuerung die n8n-Freigabe.

Für die Aktivierung muss `epss_enabled: true` in den persistenten Konfigurationen
des Importers, seiner API-Kopie und des Enrichers sowie in
`automation.workflow_settings.source_config` gesetzt sein. Die V5-Git-Quelle und
optional KEV bleiben erhalten; EPSS ist ein getrennter Tagesdatenstrom.
Die regelmäßige n8n-Aktualisierung lädt EPSS, solange noch kein vollständiger Stand
des aktuellen UTC-Tages vorliegt. Bereits laufende Aufträge werden wiederverwendet.
Nach Veröffentlichung des Tagesstands genügt ein erfolgreicher Import; ein manueller
Aktualisierungsauftrag darf auch danach Korrekturen abrufen. Vor Veröffentlichung
kann FIRST noch den Vortag liefern; dieser behält sein tatsächliches Bewertungsdatum.
Fehlgeschlagene Läufe folgen dem bestehenden Retry- und Checkpointverfahren.

HTTP läuft direkt mit geprüftem TLS zum freigegebenen FIRST-Host. Relative Redirects
zu Tagesdateien auf demselben Host und der tatsächliche Dateityp `binary/octet-stream`
werden unterstützt. Typische Fehler:
TLS/Redirect/Downloadlimit, Gzip-CRC/EOF, falsche Metadaten, abweichendes Datum, doppelte IDs,
ungültige Dezimalwerte, zu wenig Zeilen oder Rückgang unter die Mindestquote. Jeder dieser
Fehler verhindert die Current-Aktivierung. Der vorherige Datenstand behält sein tatsächliches Datum.

Die normale Mindestgröße beträgt 100.000 Zeilen, Mindestquote 0,9. Abweichungen sind nur
bewusste geschützte Konfiguration innerhalb der Modellgrenzen. Kleine automatisierte Tests
verwenden ausschließlich eigene Projekte/Profile. Keine API-Schleife pro CVE, kein stiller
Hostwechsel, kein TLS-Downgrade und keine CVE-Massenrevision bei neuer Wahrscheinlichkeit.

`epss_batch_size` steuert unabhängig vom CVE-Enrichment die Pakete des CSV-Parsers
und der Datenbankschreibvorgänge (Standard 10.000, maximal 20.000 Zeilen).
Erst nach vollständiger Prüfung wird der neue Datenstand atomar aktiviert.
Das vorhandene Ereignis `cve.enrichment.epss_updated` erzeugt über n8n einen
paginierten `findings.refresh_priority`-Auftrag für bestehende Findings. Native
V5-Dokumente werden dabei nicht umgeschrieben. Die Findings zeigen Wahrscheinlichkeit,
Perzentil, Bewertungsdatum, Modell und Aktualität. Eine Änderung der Priorität durch
EPSS erfolgt nur nach einer bereits ausdrücklich konfigurierten Risikorichtlinie.
