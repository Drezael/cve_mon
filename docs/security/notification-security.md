# Sicherheitsgrenzen Phase 19

notification besitzt ausschließlich eigene Fachschreibrechte in automation; Quellen,
Findings, Benutzer, ACLs und Serverorganisation bleiben read-only. n8n_app besitzt keine
CONNECT-Berechtigung zu cve_monitoring. Neue Security-Definer-Funktionen haben festen
pg_catalog-search_path, explizite Session-/Rollenprüfungen und keine PUBLIC-Freigabe.

Die Browser-API unter /api/v1/dashboard/notifications nutzt bestehendes Ingress-Gate,
Server-Sitzungen, CSRF und frische RBAC-/ACL-Abfragen. Eigene Präferenzen erhalten User aus
der Sitzung. Regel-/Templateänderungen erfordern separate Adminrechte und frische MFA.
If-Match ist obligatorisch; initiale Präferenzen/neue Regeln verwenden die starke Version
"0". Bestehende Versionen werden unveränderlich angehängt. Freie Actor-/Empfängerfelder
und unbekannte Felder werden zurückgewiesen. Listen filtern Rechte vor Count/Pagination.
User Admin erhält keine impliziten Schwachstellen-Benachrichtigungsrechte.

Notification- und n8n-Namespaces erlauben nur konkrete eigene Peers, PostgreSQL, DNS und
lokalen Healthverkehr. Kein Subnetz-Allow, direkter Egress, Hostport oder Docker-Socket.
Interne APIs haben TLS, Schlüsselrotation, gebundene Auftragsreferenzen und Größenlimits.
SMTP ist mTLS-gesichert; keine freie Mail-API, unkontrollierten Adressen oder ungesicherten
Zustellcallbacks. Die technische Finding-Bewertung bleibt außerhalb dieser Schreibgrenze.
