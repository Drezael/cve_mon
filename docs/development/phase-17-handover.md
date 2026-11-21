# Übergabe an Phase 18

Matching-Ergebnisse stammen aus matching.result_revisions, Komponenten aus component_results,
Belege/Konflikte aus result_evidence/result_conflicts, Abdeckung aus coverage. Der stabile
Schlüssel ist (server_id, identity); matching.current_evaluations liefert Revision,
current_version und is_current. Historische Revisionen sind unveränderlich.

matching.created/replaced/basis_changed/status_changed/affected_confirmed/
not_affected_confirmed/unclear/lifecycle_excluded enthalten ausschließlich Referenzen und
Status. Consumer müssen die monotone current_version beachten, den autoritativen Pointer
erneut prüfen und Wiederholungen idempotent behandeln. Eine wiederkehrende Revision-UUID
kann eine neue Publikation sein. Kein unbedachtes Deduplizieren nur nach UUID.

Die Ereignisse ändern keine Findings. Die alte Finding-FK zeigt noch auf matching.results;
Phase 18 muss diese bewusst migrieren. Komponenten-not_affected entwarnt nicht global;
unknown, potentially_affected, fehlende Resultate oder is_current=false sind kein automatischer
Schließungsgrund. Ein Lebenszyklusausschluss benötigt eine gesonderte Finding-Policy.

Ubuntu-API-Negativaussagen bleiben ohne verifizierte OVAL-Evidenz eingeschränkt. CPE-Zuordnung,
OSV-GIT ohne Graph und Containerpakete ohne SBOM bleiben Unsicherheiten. CVSS/KEV/EPSS sind
separate Risiko-/Priorisierungsdaten. Phase 17 installiert keine Findings-Zustellroute.
