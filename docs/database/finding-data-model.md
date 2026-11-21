# Finding-Datenmodell

00024_finding_management und 00025_finding_commands erweitern findings.findings datenhaltend.
Model 1 bleibt Legacy; alte CVE-/Matching-/Finding-Verweise und Historien werden nicht gelöscht.
Model 2 verwendet eindeutiges (server_id,cve_id), einen FK zum realen Enrichment-CVE und
zusammengesetzte FKs für Matching/Resolution derselben Server/CVE-Identität.

Ein unveränderliches Episode-Opening hat eine Nummer und einen ersten Matching-Beleg.
Ein separater immutable Closure dokumentiert technical_fix oder scoped false_positive;
ein False-Positive-Abschluss wird nicht als technische Resolution ausgegeben. match_observations
ordnet Publikationen und immutable Resultate zu. event_receipts dedupliziert Source-Events.
Die monotonen Publikationsversionen sichern auch A→B→A ab.

policy_versions ist immutable; active_policy enthält den kontrollierten aktuellen Verweis.
priority_history, deadlines und escalations erhalten alle Entscheidungen. current_findings
berechnet aktuellen technischen Bezug, Snapshot-Alter, Ausnahmegültigkeit, Bearbeiterrechte
und Überfälligkeit. DB-Bindungs- und Actor-Guards sowie der deferred Audit-Commit-Constraint
sichern die fachlichen Referenzen. Keine automatische Retention oder Cascade-Löschung.
