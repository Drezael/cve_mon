# Sicherheit Finding Management

Workeridentität findings_writer mit eigenem privatem Passwortfile und TLS verify-full.
Keine Writes auf Inventare, CVE-Rohdaten, Enrichment, Matching, Benutzer, ACLs, Gruppen,
Primärgruppen, Sortierungen, Tokens oder Zertifikate. api_security hat für neue Finding-
Tabellen nur Lesezugriff und eng begrenzte SECURITY-DEFINER-Kommandos. Kein Browserfeld
wählt DB-Rollen oder Akteure. Manuelle Aktionen werden nicht durch technische Jobs gefälscht.

GET/POST /api/v1/findings laufen auf der bestehenden Dashboard-Origin durch denselben
privaten Nginx-Gateway wie die übrigen Browserfunktionen. Sitzungsprüfung und finding:read
sind obligatorisch; Mutationen zusätzlich finding:update, aktuelle findings_manage-ACL,
CSRF und ETag. close/review:confirm/exception:approve/policy:manage benötigen gesonderte
Rechte und frische MFA. Die bestehenden Rollen erhalten keine pauschalen neuen Analyst-
Schreibrechte. Nur die expliziten neuen privilegierten Aktionen werden Admin zugeordnet.

ACL-Prädikate werden vor Listenfiltern, Pagination und Kennzahlen in SQL angewendet.
Historie, Evidenz und Exporte der gleichen Daten unterliegen derselben Objektsichtbarkeit.
Archivierte Server bleiben autorisiert historisch lesbar, sind aber nicht mutierbar.
Sortierfelder sind allowlisted; Texte und Werte sind SQL-Parameter und Plaintext, kein Code.

Container: nicht root, read-only, cap_drop ALL, no-new-privileges, begrenzte CPU/RAM/PIDs/
Dateideskriptoren, nur cve_data, kein Hostport, kein Docker-Socket. Namespace-Guard erlaubt
nur eigenes PostgreSQL, Docker-DNS, lokale Healthprobe und Antwortverkehr. Ein namespace-
gebundener Proof sperrt Claims und Readiness bis zum installierten Guard. Kein Internet,
SMTP oder Zielserverzugriff. Logs enthalten feste Fehlerklassen statt Payloads oder Secrets.
