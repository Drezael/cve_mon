# ADR-0033 – Quellengetrennte Rohimporte

Status: angenommen, 08.11.2026. Grundlage ist der tatsächliche Stand nach Phase 14.

Die Legacy-CVE-Revisionen verlangen eine CVE-ID und können eigenständige USN-/OSV-Advisories
nicht verlustfrei ausdrücken. Migration 00020 ergänzt daher quellenbezogene Records,
unveränderliche Revisionen, Artefakte, Beobachtungen, Aliase, Streams und Importläufe im
vorhandenen Schema `cve`. Die fünf registrierten IDs bleiben `cve_list`, `nvd`, `cisa_kev`,
`ubuntu`, `osv`; `cve_list` ist bewusst der bestehende Name für CVEProject.

PostgreSQL berechnet den Inhalts-SHA über seine UTF-8-JSONB-Textdarstellung. Das unterscheidet
sich ausdrücklich vom SHA der originalen Downloadbytes beziehungsweise Archivdatei. JSONB
bewahrt semantische Quelldaten, keine JSON-Whitespace- oder Schlüsselreihenfolge. Bei einzeln
abgrenzbaren Originaldateien kommt deren exakter Record-SHA hinzu. API-Seiten bleiben über
Artefakt und Position nachweisbar.

Für CVEProject wird der tägliche Baseline-Stand mit dem kumulativen Tagesdelta kombiniert.
Ein Tageswechsel im inkrementellen Modus erfordert explizite Reconciliation. Das vermeidet
stillschweigende Lücken ohne unbewiesene Annahmen über die Aufbewahrung älterer Release-Assets.
Ubuntu bietet keine dokumentierte Änderungsfilterung: CVE-Statusströme werden nach `updated`
absteigend mit Überlappung gelesen, Notices vollständig abgeglichen. OSV verlangt explizite
Ökosystemwahl; ein globaler automatischer Komplettimport ist nicht konfiguriert.

Ein über dem begrenzten HTTP-Wartebudget liegendes Retry-After beendet den Lauf kontrolliert
als `partial` mit `retry_after_exceeds_budget`. Es gibt keine automatische vorzeitige
Wiederholung. Der Betreiber wartet die Quellfrist ab und startet explizit neu.

Die Phasendatei enthält am Ende eine Vorlage für einen einzelnen Analyseauftrag. Die
explizite Benutzeranweisung zur vollständigen Umsetzung autorisiert alle 45 Aufträge.
