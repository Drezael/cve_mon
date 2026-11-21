# ADR-0035: Revisionsgebundenes Offline-Matching

Status: angenommen, Phase 17. Die alten Matching-Resultate referenzieren das Legacy-CVE-
Modell; die aktuelle fachliche Grundlage sind immutable Inventarsnapshots und Enrichment-
Revisionen. matching.runs bleibt bestehen, neue Resultat-/Evidenz-/Coverage-Strukturen
binden die tatsächlichen Eingabepaare über Fremdschlüssel. Alte Finding-Verweise bleiben
bis zur bewussten Migration in Phase 18 erhalten.

Entscheidung: gemeinsame PostgreSQL-Worker, bidirektionale strukturierte Suchindizes,
native Debian-/RPM- und ausdrücklich passende SemVer-Semantik. Historische Entscheidungen
werden nie überschrieben. Publikation sperrt Serverstatus und beide Current-Pointer;
Outbox und monotone Publikationsversion werden im selben Fachcommit geschrieben.

Folge: fehlende Identitäts-/Release-/Source-/CPE-/Commit-/SBOM-Information bleibt Unsicherheit.
Globale Entwarnung wird ohne exhaustive Abdeckung nicht behauptet. Ubuntu-API-Negativdaten
ersetzen keine verifizierte OVAL-Evidenz. Das Ergebnis referenziert die unveränderliche
Affected-Aussage per Pointer/Hash und bewahrt tatsächliche Vergleichsoperanden. Keine neue
Datenplattform, kein zusätzlicher Broker, keine externen Matcherabfragen, keine Findings.
