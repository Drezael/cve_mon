# Abdeckung

Coverage dokumentiert pro Snapshot die Erfassungszustände, nicht zuordenbare Aussagen,
fehlende Container-Paketinformationen und die offene laufende Kernelzuordnung. Vollständige
Paketlisten betreffen ihren erfassten Paketmanagerbereich; sie sind keine vollständige
Liste aller CPE-Produkte, Laufzeitbibliotheken oder Containerpakete.

Einzelne negative Komponenten bleiben einzeln referenzierbar. Ohne vollständige relevante
Identitätsabdeckung bleibt die globale Nichtbetroffenheit unbelegt. global_negative=false
ist ausdrücklich keine Schwachstellenaussage. Fehlender Resultatdatensatz bedeutet ungeprüft.
matching.indexed_revisions.unmapped_count erfasst nicht indexierbare Source-Aussagen.
Nicht indexierte Altbestände benötigen einen expliziten Backfill. Stale Ergebnisse sind
in current_evaluations.is_current sichtbar und dürfen von Phase 18 nicht als aktuell gelten.

## Versionsbereiche und Regelupgrade

Die CVE-Datenansicht zeigt dieselbe `version_support`-Matrix wie der interne
API-Vertrag. Debian/Ubuntu, RPM und SemVer haben explizite Comparatoren. Python,
Java/Maven, Go, Alpine, RubyGems, Composer und NuGet besitzen derzeit keinen
allgemeinen Bereichscomparator. Explizite OSV-Versionen können trotzdem verwertbar
sein; unbekannte Bereiche bleiben unbestimmt. Priorität für weitere Adapter haben
Python und Alpine, sobald reale Inventarzähler deren Bedarf belegen; daraus wird
keine Upstream-Versionsheuristik für Distributionspakete abgeleitet.

Migration 00076 registriert `matching-2`. Bereits vorhandene Resultate von
`matching-1` bleiben historische Evidenz und werden als veraltet angezeigt.
Nach Ausrollen der neuen Worker den vorhandenen seitenweisen Backfill anstoßen:

```sh
.venv/bin/python -m scripts.cve_matcher.manage enqueue --kind backfill
```

Der Backfill ergänzt zunächst Suchschlüssel aller aktuellen Revisionen und baut
anschließend die Inventarindizes und Entscheidungen neu auf. Die Regelversion ist
Bestandteil des Resultatfingerprints; ein alter Cachetreffer kann die korrigierte
Entscheidung deshalb nicht ersetzen. Bei Überschreiten des Struktur-, Komponenten-
oder Bytebudgets schlägt der einzelne Job fehl, ohne einen Teillauf zu publizieren.
Bei NVD zählen nur logische Knoten zur Tiefe (höchstens 32), insgesamt höchstens
4.096 Knoten/Blätter. CNA unterstützt höchstens 4.096 Versionszeilen vollständig.
