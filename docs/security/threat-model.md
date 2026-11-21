# Bedrohungsmodell T00.02.06

Schutzgüter: lokale CVE-/Inventarhistorie, Integrität der Bewertungen, administrative
Serverorganisation, Benutzer-/MFA-/Tokengeheimnisse, Verfügbarkeit und nachvollziehbares Audit.
Vertrauensgrenzen: Internet→Nginx, Browser→API, Ansible→Submit, Dienst→Dienst,
Dienst→PostgreSQL, Proxy→Quelle/Smarthost, Betreiber→Volumes/Schlüssel.
Gruppen-/Sortierisolation ist eine überprüfbare Sicherheitsinvariante.

| Fläche | Bedrohung | Voraussetzung | Schaden | Schutz | Zuständig | Restrisiko | Späterer Nachweis |
|---|---|---|---|---|---|---|---|
| Öffentliches HTTPS | Unberechtigter Zugriff / Brute Force | Öffentlicher Endpoint | Kontoübernahme, Datenabfluss | TLS, gleichförmige Loginfehler, Rate-Limits, TOTP, aktuelle Sitzung | Nginx / API | Gestohlene gültige Sitzung bleibt zeitweise nutzbar | Login-/MFA-/Widerrufstests |
| mTLS-Submit | Identitätsfälschung / Header-Spoofing | Angreifer setzt Zertifikatsheader oder gestohlener Token | Fremdinventar | Pflicht-mTLS UND certgebundener Token; vertrauensgebundener Nginx-Peer | Nginx / API | Kompromittierter Controller kann seine erlaubten Serverdaten fälschen | Ohne Zertifikat, falscher SAN, Header-Spoof, anderer Server |
| Dashboard-Upload | Manipulierte Upload-Daten / Ressourcenerschöpfung | Sitzung mit Uploadrecht | Speicher-/CPU-Last, verfälschte Daten | 10-MiB-Limit, striktes Schema, begrenzte Arrays, Timeouts, keine Archive | API / Inventory | Legitime große Inventare benötigen später gemessene Limits | Übergröße, tiefe/unerlaubte Struktur, ungültiges UTF-8 |
| Upload/Matching/Outbox | Manipulation administrativer Gruppen | Fremde group_ids oder event payload | Privilegien-/Objektbereichswechsel | Geschlossene Objekte, getrennte Rollen und keine Organisations-Trigger | API / Inventory / Dispatcher | Vollständig kompromittierter API-Prozess besitzt mehrere Pools | Verschachtelte Gruppenfelder und PostgreSQL-Grant-Deny |
| Gruppen-/Benutzerverwaltung | Privilegieneskalation / IDOR | Unzureichend berechtigter Benutzer | Fremde Server, neue Adminrechte | Aktionsrecht plus Objektprüfung, Delegationsgrenzen, MFA, If-Match | API | Fehler in Autorisierung oder Betreiberzugriff | Nicht berechtigtes Objekt, parallele letzte-Admin-Änderung |
| Browseraktionen | CSRF | Gültiger Cookie im Browser | Ungewollte schreibende Aktion | Origin-Prüfung, sitzungsgebundener CSRF-Token, SameSite | Dashboard / API | XSS kann CSRF-Schutz umgehen | Fehlender/falscher CSRF für Upload und Admin |
| CVE-/Inventar-/Reportansicht | XSS / CSV-Injektion | Manipulierte Quelltexte oder Paketnamen | Sitzungsmissbrauch / lokale Formelausführung | Kontextbezogen escapen, CSP, keine Raw-HTML-Ausgabe, CSV-Formeln entschärfen | Dashboard / Reporter | Neue Ausgabeformate benötigen eigene Prüfung | HTML-/Formelpayload in synthetischen Quellinformationen |
| PostgreSQL/API | SQL Injection | Ungeprüfte Such-/Sortier-/IDs | Datenverlust oder Rechteumgehung | Parametrisierte Abfragen, Allowlistfelder, Minimalrollen | Alle DB-Clients | DB-Owner bleibt privilegiert | SQL-Payloads, keine freien Spalten-/Rollennamen |
| Interne APIs | Dienst-Spoofing / Confused Deputy | Netzzugang oder gestohlener Service-Nachweis | Unberechtigte Jobs/Writes | mTLS, aud/expiry, Caller-Allowlist, Actorprüfung und Idempotenz | API / Fachdienste | Kompromittierter autorisierter Dienst innerhalb seines Scopes | Falsche Audience, abgelaufener Nachweis, fehlender Actor |
| Envoy / Importe | SSRF / DNS-Rebinding / Netzwerkumgehung | Manipulierte URL, Redirect oder DNS-Antwort | Metadaten-/interne Datenabfrage | Feste Zielhost/Port-Allowlist, Adressprüfung, Host-Firewall auch IPv6 | Envoy / Importer / Enricher | Öffentliche erlaubte Quelle kann kompromittiert sein | Private/AAAA/mapped-IP-Ziele und direkte Egress-Versuche |
| Statuspage | SSRF / Rechteumgehung | Browser liefert Ziel oder Protokoll | Interner Portscan / Secretabfluss | Festes Manifest, keine Queryziele, begrenzte Parallelität, no-store | API / Statusdienst | Direkter Check beweist nicht jede Fachfunktion | Zielparameter ablehnen, Teiltimeouts und neue Prüfung |
| Credentials / Backup | Secret-Diebstahl | DB-Dump, Log oder Dateizugriff | Sitzungs-/MFA-/Dienstübernahme | Nur Verifikatoren, TOTP-Verschlüsselung, externer Key, restriktive Mounts | API / Betreiber | Schlüssel plus DB zusammen kompromittiert | Secret-Scan, Dump-/Logprüfung, Schlüsselrotation |
| Lokale Daten / Queue | Datenverlust | Disk voll, Defekt oder fehlerhafte Löschung | Verlorene Historie/Jobs/Mails | Persistente Volumes, Transaktionen, RESTRICT, Backups und Restoretests | PostgreSQL / Postfix / Betreiber | RPO/RTO ohne spätere Messung unbekannt | Disk-/Commitfehler, Restore inklusive Schlüssel/Queue |
| CVE-Datenimport | Datenvergiftung / Parsermissbrauch | Bösartige Quellrevision | Falsche Bewertung / DoS | Limits, sichere Parser, Quellenprovenienz/Hash, Unknown statt Ratenergebnis | Importer / Enricher / Matcher | Authentische Quelle kann inhaltlich falsch liegen | Kaputte Revision, Quoten, Ubuntu-Backport, Provenienz |
| Jobs / n8n / Outbox | Replay / doppelte Verarbeitung | Verlorene Quittung oder Lease-Ablauf | Doppelte Berichte/Mails oder veraltete Writes | Persistente Idempotenz, Fencing, SKIP LOCKED, bounded Retrys | Dispatcher / Worker / n8n | SMTP kann nach Quittungsverlust doppelt zustellen | Lease-Wettlauf, mehrfaches Event, Crash nach Commit |
| SMTP | Abhören / falsches Zertifikat / Open Relay | Externer Tunnel oder falscher Smarthost | Mailabfluss / Spammissbrauch | Fester TCP-Upstream, STARTTLS mit externem FQDN, AUTH, nur Notification als Relayclient | Postfix / Envoy | Externer Mailanbieter sieht notwendige Empfängerdaten | Server-first, fehlendes TLS, Namensfehler, fremder Relayclient |

Nicht behauptet wird Schutz gegen einen bereits vollständig privilegierten Hostbetreiber.
Ein kompromittierter API-Prozess kann mehrere dort bereitgestellte Kontext-Credentials gefährden;
getrennte Pools sind keine Prozessisolation. Spätere Härtung muss dieses verbleibende Risiko
bewerten, ohne technische Uploads regulär zum Admin-Kontext zuzulassen.
[Prüfszenarien](../testing/architecture-acceptance-scenarios.md) konkretisieren API-/DB-Wirkungen.


## Phase-23-Abgleich des tatsächlichen Stands

Die vorstehenden ursprünglichen Phasenannahmen sind gegen den implementierten Stand abzugleichen: Browser- und Inventarzugang verwenden die bestehenden unterschiedlichen Identitätswege, Notification/n8n verwenden TLS plus ihre festen Dienstnachweise. Es gibt keine allgemeine zweite JWT-/mTLS-Autharchitektur für sämtliche internen APIs. Lokale fest adressierte Healthsignale können HTTP verwenden und besitzen keine administrative Fachfunktion. Status besitzt ein eigenes Schema innerhalb der vorhandenen API und keine neue Runtimekomponente.

STRIDE-Prüfung umfasst Identitätsfälschung an Nginx/Client/Gateway, Payload-/Evidenz-/Auditmanipulation, Abstreitbarkeit von Mutationen, Informationsabfluss über DTOs/Logs/Backups, Ressourcenerschöpfung über Parser/Queues/teure Queries und Privilegieneskalation über Rollen/ACLs/Container. Zusätzliche explizite Grenzen sind Host zu Container, Statuscollector zu lokalen Adaptern, Backup zu unabhängiger Schlüsselablage und Build/Scanner zu veröffentlichtem Artefakt. Alle14 im Phasenkonzept genannten logischen Grenzen sind dadurch vertreten; das Diagramm ist kein zusätzliches Docker-Netzwerkmodell.

Die [Baseline](security-baseline.md), [Kontrollzuordnung](asvs-mapping.md), [Befunde](security-findings.md) und [Restrisiken](residual-risks.md) dokumentieren den tatsächlich geprüften Stand. Hohe/kritische Imagebefunde bleiben ein Freigabeblocker. Vorhandene Netz-/Authisolation ist keine pauschale Nichtbetroffenheitserklärung.
