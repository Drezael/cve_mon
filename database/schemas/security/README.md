# Security-Schema

Die bestehenden Benutzer-, Rollen-, Credential-, Session-, MFA-, Recovery-, Token- und
Auditstrukturen aus Phase 3 bleiben erhalten. Revision 00014_authentication ergänzt
die lokale Authentifizierung, ohne allgemeine Benutzerverwaltung zu aktivieren.
CSRF/origin/auth_version/idle_expires_at/last_used_step aus 00010 werden wiederverwendet.
Neue Credential-Versionen, technische Sessionzustände/runtime_version, Enrollmentbindung,
HMAC-Rate-Buckets, anonyme CSRF-Kontexte und sichere Aggregate. Alte Sessions/Faktoren
werden nicht stillschweigend als neue Laufzeit übernommen.

api_security besitzt die vorgesehenen beschränkten Security-Rechte und keinen Gruppen-
Schreibzugriff. Reader bleibt api_reader; status_probe nur auth_metrics. Bootstrap und
90-Tage-Archiv-Purge sind eng begrenzte cve_migrator-Funktionen mit festem search_path.
Audit-Aktionskatalog ausdrücklich ergänzt; RLS und vorhandene Fachrechte bleiben erhalten.
[Betrieb](../../../docs/operations/authentication-troubleshooting.md).

Phase 9 / Revision 00015 ergänzt endliche menschliche Rollenrechte, Rollenrevisionen,
vorhandene Server-ACL-Flags mit UUID/Erteiler/Zeit, server_acl_versions als Setrevision,
recovery_requests und geschützten administration_state. Keine doppelte Benutzer-/ACLhaltung.
Legacy effective_server_access enthält Gruppenvereinigungen und ist keine gültige Browser-
Autorisierungsquelle. Native deferred Last-Admin-Constraints, geschützte Systemrollen,
nondelegable custom permissions und frische Serviceprüfungen ergänzen sich.
[Autorisierungsarchitektur](../../../docs/architecture/authorization.md).

Phase 11 / Revision 00017 ergänzt öffentliche technische Zertifikate, gebundene
runtime_version=1-Tokens und eng begrenzte identity/rate/metric-Funktionen. Verifikatoren
sind HMACs mit privatem Dateischlüssel; Klartext und Client-Privatschlüssel werden nicht
persistiert. Laufzeit-1 verlangt genau einen Server, registriertes Zertifikat, Client und
festen Scope. Legacy-Tokens sind keine gültigen Uploadcredentials.
[Technische Credentials](../../../docs/security/inventory-api-tokens.md).
