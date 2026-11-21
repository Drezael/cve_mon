# OSV und Versionsregister

| Semantik | Adapter | Zulässige Verwendung |
|---|---|---|
| SEMVER | semver-2 | expliziter OSV-SEMVER-Bereich; striktes SemVer 2.0.0 |
| ECOSYSTEM npm/crates.io | semver-2 | nachgewiesenes passendes Paketökosystem |
| ECOSYSTEM Debian[:Release]/Ubuntu:Release[:LTS] | dpkg-1 | belegtes Quellpaket mit eigener vollständiger Version und passendem Release |
| andere ECOSYSTEM | keiner | potentially_affected / unsupported_comparator |
| GIT | keiner | git_graph_unavailable; kein Commitgraph wird erfunden |

Ubuntu-OSV bezeichnet Quellpakete und benötigt den numerischen Release; Pro benötigt einen belegten ESM-Kanal. Debian darf einen expliziten Release-Suffix tragen. introduced 0 bezeichnet den unbegrenzten unteren Anfang. fixed ist exklusiv,
last_affected inklusiv. limit wird getrennt von der zeitlichen Statusfolge ausgewertet; mehrere Limits vereinigen den erfassten Bereich, * ist unendlich. Außerhalb des Limits liefert der Rangeadapter false, die Entscheidung bleibt wegen der eingegrenzten Quellabdeckung unbekannt. Limits sind keine Fixnachweise. Unsortierte gültige Ereignisse werden mit dem passenden Versionsadapter sortiert. Mehrere Intervalle werden vereinigt; explizite
versions-Listen können Betroffenheit bestätigen. Eine nicht ausgewertete Range hebt
negative Schlussfolgerungen aus anderen Ranges auf. Ungültige Ereignisfolgen bleiben offen.
SemVer akzeptiert keine v-Präfixe, fehlenden Komponenten oder führenden numerischen Nullen;
Build-Metadaten ändern die Priorität nicht. Cache: höchstens 8192 Adapter-/Operandenpaare.
[OSV-Schema](https://ossf.github.io/osv-schema/), [SemVer](https://semver.org/spec/v2.0.0.html).
