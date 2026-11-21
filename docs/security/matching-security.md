# Matcher-Sicherheit

Eigene technische Rolle matcher; TLS verify-full mit eigenem privaten Passwortfile und CA.
Keine Schreibrechte auf Inventare, CVE-/Enrichment-Daten, Serveradministration, Gruppen,
Benutzer, Tokens, ACLs oder Findings. Keine SET ROLE-/Superuser-Laufzeit. Legacy-Resultate
sind für neue Writes gesperrt. Publikation ausschließlich durch die enge DB-Funktion.

Container: nicht root, read_only, cap_drop ALL, no-new-privileges, begrenzte CPU/RAM/PIDs/
Dateideskriptoren, nur internes cve_data, keine Hostports, kein Docker-Socket. Der Host
installiert im eigenen verifizierten Namespace einen nftables-OUTPUT-Guard: ausschließlich
Docker-DNS, eigenes PostgreSQL:5432, lokale Healthprobe und Antwortverkehr. Kein Envoy-
Zugang, kein Internet oder Zielserver. Worker und Readiness sind bis zum namespacegebundenen
Guard-Proof geschlossen. Neustarts mit neuem Namespace erfordern erneute Guardinstallation.

SQL bindet alle Nutzwerte als Parameter. Paketnamen, Versionen und Ausdrücke werden nie
als Befehle ausgeführt. Parser und Batches sind begrenzt. Logs verwenden gemeinsame
strukturierte Redaction und feste Fehlercodes; keine Rohinventare oder Secrets.
