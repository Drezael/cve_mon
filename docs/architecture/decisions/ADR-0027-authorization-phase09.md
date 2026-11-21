# ADR-0027 – Endliches RBAC, explizite Browser-ACLs und letzte Administration

Status: accepted. Datum: 06.11.2026.

API 0.9.0 verwendet die Phase-8-Identität und bestehenden Securitytabellen. Additive
Revision 00015 ersetzt Wildcard-Planungsseeds durch exakt 38 menschliche Rechte und
vier Systemrollen. Maschinen-/Legacyrechte werden nicht in der Browserengine ausgeführt.
Zusätzliche Rollen nur delegierbar/nichtadministrativ, Systemrollen nativ durch RLS geschützt.

Serverfreigaben bleiben in user_server_access mit vier expliziten Fähigkeiten und getrennten
ACL-Setrevisionen. Kein Browserzugriff über gruppenvereinigende Legacy-Views. SQLfilter vor
Suche/Pagination/Aggregation. Admin-Lesen ausdrücklich erlaubt, Upload auch für Admin nur
mit gesondertem ACL. Keine Server-/Gruppen-/Upload-Fachfunktionen vor Folgephasen.

Router und Service prüfen getrennt gegen frische Daten. Shared-/Exclusive-Advisory-Locks
serialisieren Berechtigungsentzug und laufende kontrollierte Transaktionen; kein Cache.
Kritische Mutationen verbrauchen Phase-8-Reauth. Native deferrable Constraints verhindern
null nutzbare Admins nach dem einmaligen Bootstrap. Keine Runtime-Ausnahme und kein Notfallkonto.

Manuelle Aktivierung/Recovery verwenden separate kurzlebige account_tokens, nur Hash in
PostgreSQL und Klartext in privatem explizitem Operator-Handoff. Admin-MFA-Recovery ist
eine Anfrage mit anderem stark bestätigtem Admin und unabhängigem Operator, keine
unbeschränkte Session oder Secretanzeige. Actor/Ziel/Audit/Outbox atomar; Denials begrenzt.
Keine neue Infrastruktur oder externen Abhängigkeiten. Gemeinsame Bibliothek bleibt 0.7.0.
