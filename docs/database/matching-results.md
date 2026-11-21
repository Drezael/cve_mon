# Matching-Persistenz

Migration 00023_matching_engine ist additiv und datenhaltend. matching.runs bleibt das
Laufmodell; job_id/correlation_id/trigger_type ergänzen den technischen Kontext. run_inputs
und candidates fixieren Enrichment-Revision und CVE. result_revisions besitzt UUID,
Snapshot-/Serverbindung, Regelversion, Status/Grund, strukturiertes Ergebnis und SHA-256-
Fingerprint über Snapshot-ID, Enrichment-ID und matching-1. Identische Inputs deduplizieren.

component_results bewahrt jede Installation separat und bindet Paket-UUID und Snapshot per
zusammengesetztem FK. result_evidence/result_conflicts/coverage referenzieren die Revision.
Append-only-Trigger sperren UPDATE/DELETE auch für den Tabellenowner; versiegelte Kinddaten
können nicht in späteren Transaktionen ergänzt werden. Evidenzprovenienz muss zu den
Enrichment-Eingaben gehören. rule_versions hält Vergleichsadapter und Versionen fest.

current_results hat keinen direkten Matcher-Schreibzugriff. matching.publish ist SECURITY
DEFINER mit festem pg_catalog-Suchpfad und session_user-Prüfung; Server- und beide
Input-Pointer werden gesperrt und geprüft. Publication und Outbox sind atomar.
current_evaluations weist aktuelle und veraltete Grundlagen ausdrücklich aus.

Bidirektionale B-Tree-Indizes auf vulnerability_keys und inventory_keys vermeiden ein
Server×CVE×Paket-Produkt. Durch immutable Revisionen sind alte Indizes historisch gebunden.
Die Legacy-Tabelle matching.results wird nicht befüllt. Phase 18 muss die bestehende
Finding-Referenzstruktur ausdrücklich anpassen, bevor neue Resultate übernommen werden.
