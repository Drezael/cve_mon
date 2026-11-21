# Collector, n8n und Live-Cache

Die aktuellen Dienstzustände, einzelnen Healthchecks und kurzzeitigen Messreihen
liegen im RAM des bestehenden API-Prozesses. Es ist kein zusätzlicher Container
nötig. Die Status-API liest diese Werte aus `StatusCache`; sie fragt dafür weder
`status.current_states` noch `status.check_observations` noch die Job-Historie ab.
Anmeldung, Berechtigungen und Wartungsfenster verwenden weiterhin die Datenbank.

n8n gibt die regelmäßigen `status.collect`-Aufträge über die vorhandene Queue frei.
Der Collector prüft feste Ziele parallel und veröffentlicht ein vollständiges
Messergebnis synchron im Cache, bevor dauerhafte Vorfälle gespeichert werden.
Stabile Messungen schreiben keine aktuellen Zustände oder Rohmessungen in PostgreSQL.
Nur Vorfalländerungen, Audit und die n8n-Ausführungsbelege bleiben persistent.
Schlägt die Vorfallspeicherung fehl, bleiben die aktuellen Messwerte abrufbar;
offene Änderungen werden beim nächsten Auftrag erneut gespeichert.

Healthchecks haben ein eigenes Zeitlimit. Zusätzliche Datenbankdiagnosen für
Queues, CVE-Aktualität und Abdeckung laufen getrennt und ebenfalls mit Zeitlimit.
Ein langsamer Diagnoseaufruf verwirft keine erfolgreichen HTTP-Healthchecks.
Unbekannte Zusatzmetriken überschreiben keinen frisch bestätigten Dienststatus.
Tatsächliche Readiness-Ausfälle, veraltete Messwerte und fehlende Abdeckung bleiben
sichtbar. Der Fehlerabgleich gegen die Job-Historie verwendet einen passenden
Index auch für Jobs ohne Runtime-Version-Filter.

Messwerte veralten nach 180 Sekunden. Ein Seitenaufruf verlängert diese Frist
nicht. Duplikate und ältere Prüfungen überschreiben keine neueren Messwerte.
Pro Dienst/Prüfung sind höchstens 2.000 Punkte und pro Dienst 512 Zustandswechsel
im Speicher. Ein API-Prozessneustart leert den Cache; der nächste n8n-Prüfauftrag
füllt ihn erneut. Dauerhafte Einstellungen und Störungsvorfälle bleiben erhalten.
Die bisherigen historischen Datenbanktabellen werden nicht gelöscht; Werkzeuge
für explizite historische Diagnose bleiben kompatibel.
