# Datenaktualität und Leerlauf

Quellfristen werden ausschließlich aus expliziten status.source_expectations abgeleitet. Ohne genehmigte Quellfrist bleibt SOURCE_EXPECTATION_NOT_CONFIGURED unknown; es wird kein universeller täglicher Import erfunden. Die bestehende EPSS-Maximalalterregel von zwei Tagen wird übernommen. Matching prüft reale aktuelle Snapshots gegen current_evaluations: eine leere Queue beweist keine vollständige Bewertung. Fehlende aktuelle Evaluationen werden getrennt als uncovered angezeigt. Ein leerer Inventarbestand allein erzeugt keinen Processing-Ausfall.
