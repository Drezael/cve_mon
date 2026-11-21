# Abnahme Phase 19

Stand 09.11.2026: alle 45 Aufträge abgeschlossen. Die 160 verpflichtenden Kriterien sind
in der [Testmatrix](../testing/phase-19-test-matrix.md) einzeln zugeordnet. [Status](phase-19-status.md),
[Architektur](../architecture/notification-system.md) und [Übergabe](phase-19-handover.md)
beschreiben den ausgelieferten Stand. Keine offenen verpflichtenden Phase-19-Aufgaben.

cve-api und cve-notification 0.19.0, cve_common 0.7.0 und n8n 2.44.7 sind aktiviert.
Head: 00027_notification_commands. Alle dreizehn eigenen Dienste sind gesund. Beide
Datenbanken wurden vor der Migration unter .runtime/phase19-pre-migration gesichert.
Die zuvor leere n8n-Datenbank ist nun ausschließlich durch n8n initialisiert; sechs eigene
Workflows sind veröffentlicht, zwei Header-Credentials verschlüsselt gespeichert.

104 bestehende Fach-/Administrations-/Inventar-/CVE-/Matching-/Finding-Tabellen bleiben
per Fingerprint datenidentisch. Nur der vorgesehene Berechtigungskatalog und die
Rollenzuordnung erhalten acht neue Rechte. Die Legacy-Notification-Tabelle bleibt erhalten.
328 zuvor erfasste Python-Bestandsdateien sind hashgleich; drei bestehende API-Dateien
registrieren Router, Version und Rechte. Alte Worker, cve_common und sämtliche früheren
Migrationen sind unverändert. Die tatsächlichen Images stimmen mit dem Workspace überein:
83 API- und zwölf Notification-Pythondateien, einschließlich des Notification-Pakets im API-Image.

Die normale Umgebung enthält weiterhin keine Benutzer, Tokens, Inventarsnapshots, CVE-
Quellrecords, Enrichment-/Matching-Ergebnisse, Findings oder Notification Intents/SMTP-Versuche.
Keine Testdaten wurden übernommen. Normale Regeln und Mailfreigaben bleiben geschlossen.
Die vier fremden Nextcloud-Container sind unverändert. Envoy-Policy sowie Importer-/Enricher-
Bindungen sind unverändert. API, Postfix und Envoy wurden aktualisiert bzw. neu gestartet;
die übrigen bestehenden Container behalten ihre IDs.

Beim Aktivieren wurden abgelaufene lokale Entwicklungs-Mailzertifikate festgestellt.
Die Entwicklungs-CA wurde mit demselben privaten CA-Schlüssel erneuert; Relay- und
Notification-Zertifikate wurden neu ausgestellt. Vorherige Zertifikate liegen privat unter
.runtime/phase19-mail-pki-before-renewal. Postfix-/Envoy-Versandfreigaben und Upstream-
Credentials wurden nicht geändert. Die Mailrelay-Bindung wurde für den Neustart aktualisiert.

| Prüfung | Erfolgreiche unterschiedliche Fälle |
|---|---:|
| Notification-Regeln, MIME, HTML, DST, Adressen, Rotation und SMTP-Fehler | 36 |
| Native PostgreSQL-/Event-/Empfänger-/Digest-/Rate-/Lease-/Rechte-/Lastprüfungen | 31 |
| Browser-API, CSRF, ETag, Actor, Adminrechte, Scope und echtes HTTPS | 4 |
| Tatsächliches n8n/Image/Netzwerk, SMTP-Kette, PG-/n8n-Ausfall und SIGKILL | 11 |
| Regression Standard | 551 |
| Regression Datenbank und Jobs/Outbox | 218 |
| Regression Authentifizierung, Autorisierung und Serververwaltung | 146 |
| Regression Findings | 92 |
| Regression Postfix/mTLS/Envoy-SMTP/Queue | 36 |
| Regression Infrastruktur und bestehende API-/Service-Container | 51 |
| Gesamt ohne Mehrfachzählung | 1176 |

Der vollständige Notification-Lauf besteht mit 82 Fällen. Die Infrastruktur-Regression
besteht aus 50 erfolgreichen Fällen des Gesamtlaufs und einer erfolgreichen isolierten
Nachprüfung desselben Netzwerkfalls. Im parallelen ersten Lauf waren Dockers verfügbare
Subnetze ausgeschöpft; nach Abschluss der anderen Testprojekte bestand die Nachprüfung.
Es wird kein einzelner fehlerfreier 51er-Infrastrukturlauf behauptet. Wiederholungen zählen
nicht zusätzlich. Der reine JUnit-Hinweis zu record_property ist keine fehlgeschlagene Prüfung.

`make check` ist erfolgreich: Ruff, Formatierung, striktes Mypy für 391 Quelldateien,
551 Standardfälle, Repository-/Schema-/Compose-Validierung und Secretprüfung. Die bestehende
Secret-Baseline wurde nicht erweitert. Der Notification-OpenAPI-Vertrag wurde zusätzlich
mit openapi-spec-validator validiert. Keine Remote-CI-Ausführung wird behauptet.

Performance-Baseline: 100 zusätzliche autorisierte Empfänger mit Keyset-Seiten, realen
Finding-Ereignissen, Deduplizierung, Rechteprüfung und persistenten Entscheidungen in
35.130 Sekunden im wiederverwendeten nativen Testbestand. Die Messung umfasst dessen
bestehende Ereignisse und Server; sie ist keine allgemeine Produktionskapazitätszusage.
SMTP-Parallelität, persistente Rate Limits und begrenzte Deferrals verhindern Zustellspitzen.

Der Ende-zu-Ende-Test belegt Finding → Outbox → PostgreSQL-Worker → n8n-Webhook → interne
Claim-/Execute-API → erneute Rechteprüfung → mTLS-Postfix → vorhandener Envoy-TCP-Pfad →
synthetischer SMTP-Smarthost. Stabile Message-ID, Queue-ID, Relay-Instanz, Attempt und
Historie werden geprüft. Wiederholter Workflow/Trigger erzeugt keinen zweiten Submit.
Passive vertrauenswürdige Postfix-Beobachtungen setzen upstream_accepted idempotent.
Das ist ausdrücklich kein finaler Zustellnachweis. Unklare DATA-Annahmen bleiben gesperrt;
kein blindes Retry und keine Exactly-once-Behauptung über SMTP.

Sicherheit und Recovery sind nachgewiesen: n8n_app ohne Fach-DB-Zugriff; notification ohne
Quell-, Finding- oder administrative Schreibrechte; API ohne direkte Intent-Schreibrechte.
Aktuelle Benutzer-/Objektrechte vor Listen/Counts und erneut vor SMTP, CSRF, MFA für
privilegierte Änderungen, If-Match, keine freien Empfänger, Hosts oder ausführbaren Regeln.
Header-Injektion, unzulässiges HTML, unbekannte Felder und manipulierte Aufträge werden
abgewiesen. Private TLS-Schnittstellen, begrenzte Request-Bodys, Namespace-Guards und
persistente Schlüssel schützen den Betrieb. n8n-/PG-Ausfälle, Neustart und verlorene Leases
sind geprüft. Ausnahmevorwarnung verändert keine Finding- oder Ausnahmeentscheidung.

Passiver Live-Queuecheck: null Nachrichten; keine normale SMTP-Übergabe ausgeführt.
Ohne frische Queue-Beobachtung liefern die Metriken nach fünf Minuten ausdrücklich unknown
statt einer erfundenen leeren Queue. Fachhistorien bleiben append-only; n8n-Pruning löscht
keine Zustellhistorie. Dashboard-Oberflächen folgen in den nächsten Phasen.

Lokale Nachweise unter .runtime/test-reports: phase-19-notifications-final.xml/.log,
phase-19-test-summary.json, phase-19-final-check.log, phase-19-full-mypy.log,
phase-19-db-jobs.xml/.log, phase-19-authz.xml/.log, phase-19-findings-regression.xml/.log,
phase-19-mail.xml/.log, phase-19-infrastructure-services.xml/.log,
phase-19-isolation-recheck.xml/.log, phase-19-live-verification.json/.log,
phase-19-live-queue.log, phase-19-live-migration.log, phase-19-backup.log und
phase-19-mail-renewal.log. Keine Git-Commits oder Pushes erstellt.
