# Versionierte Priorisierung

Kein erfundener gewichteter Risikoscore. Die initiale Policy übernimmt die Severity eines
validierten bevorzugten CVSS-Metriks aus Phase 16. Ungültige oder fehlende Metriken bleiben
unrated. Aktuelle KEV-Mitgliedschaft begründet nach dieser dokumentierten Policy mindestens
high. Ein niedriger EPSS-Wert neutralisiert KEV nicht. EPSS wird erst durch eine ausdrücklich
freigegebene Schwelle prioritätswirksam; ohne Schwelle bleibt es getrennte Kontextinformation.

Die Signalsbasis enthält Metrik/Provider/Version/Vektor, dynamischen KEV-Status samt Freshness,
KEV-dueDate als Quellenangabe und EPSS-Dataset/Datum/Modell/Score/Percentile/Age/Stale. Fehlend
ist nicht null. Die tatsächliche technische Betroffenheit kommt ausschließlich vom Matcher.
Risiko-Refresh verändert keine Finding-ID und eröffnet keine Episode. Jede Bewertung hält
Policy, tatsächliche Signale, Gründe und Fingerprint in priority_history fest. Unveränderte
Signale sind idempotent. Eine neue Episode besitzt eine eigene Prioritätshistorie.
