# Übergabe an Phase 19

Neue Findings sind findings.findings.model_version=2 mit stabilem Server/CVE-Schlüssel.
current_findings liefert Lifecycle, technische Basis und Verwaltungsentscheidung separat.
Episoden/Closures, match_observations, Audit, Prioritäten, Fristen und Ausnahmen sind immutable.
Legacy-Befunde bleiben getrennt; sie werden ohne aktuelle reale Matching-Basis nicht erfunden.

finding.*-Events sind kompakte Referenzen mit Finding/Server/CVE/Episode, Row-Version, Status,
Zeit und Korrelation. Technische Ereignisse stammen von cve-findings/findings_writer;
manuelle closed/assigned/triaged/noted/reviewed/mitigated/exception*-Aktionen von cve-api/
api_security. finding.policy_changed hat einen eigenen Policy-Referenzvertrag. Source und
Schema prüfen, Wiederholungen idempotent behandeln und aktuelle Row-/Publikationsversionen
beachten. Keine Nachrichtenzustellroute ist in Phase 18 automatisch aktiviert.

Phase 19 entscheidet Benachrichtigungen, Frequenz, Ausnahmen und Kanäle. Das Finding bleibt
bei Risikoakzeptanz sichtbar und technisch betroffen. Unknown/Stale/fehlende Daten sind keine
Entwarnung. CISA dueDate ist Quelleninformation, keine universell angenommene Rechtsfrist.
Die API-/Objektrechte sind auch für spätere Dashboard- und Exportfunktionen verbindlich.
