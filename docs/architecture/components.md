# Komponentenkatalog T00.01.02

Der Katalog beschreibt die Phase-0-Zielarchitektur. In Phase 2 ist cve-nginx inzwischen
implementiert und lokal abgenommen; die übrigen Container sind weiterhin geplant. Python-Dienste verwenden
Python 3.12/FastAPI; das Dashboard ist eine eigenständige Python-Webanwendung.
Netzzuordnungen sind im [prüfbaren Architekturvertrag](../../contracts/security/service-access-v1.json)
festgelegt. Tabellenrechte stehen in der [DB-Matrix](../database/access-matrix.md).
Interne HTTP-Ports: Anwendungen 8000, cve-api 8443 für authentifizierte Nginx-Weiterleitung,
n8n 5678; alle internen Anwendungsaufrufe werden TLS-geschützt (keine öffentlichen Ports).

## cve-nginx

- Zweck/Zuständigkeit: TLS-Ingress; getrennte virtuelle Hosts, mTLS-Prüfung und begrenzte Reverse-Proxy-Wege.
- Technologie: Nginx.
- Daten/Schnittstellen: Dashboard/API/n8n; kein Datenzugriff.
- Datenbankrollen: keine; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_ingress, cve_internal. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: Host-Netz und lokale Konfiguration.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: HTTP /healthz; Readiness: zulässige Upstreams separat. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-egress-proxy

- Zweck/Zuständigkeit: Envoy: kontrollierter HTTP-/HTTPS-Forward-Proxy und fester SMTP-TCP-Tunnel.
- Technologie: Envoy.
- Daten/Schnittstellen: Nur freigegebene Quellen und SMTP-Smarthost.
- Datenbankrollen: keine; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_egress_internal, cve_egress_external. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: Host-Netz und lokale Konfiguration.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: Geschütztes /ready auf Admin-Port; keine öffentlichen Admin-Zugriffe. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-postgres

- Zweck/Zuständigkeit: PostgreSQL-Cluster mit getrennten Datenbanken n8n und cve_monitoring.
- Technologie: PostgreSQL.
- Daten/Schnittstellen: Persistente Fach-, Sicherheits- und n8n-Daten.
- Datenbankrollen: postgres_owner; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: Native SELECT 1, zusätzlich rollenbezogene Anwendungs-Readiness. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-n8n

- Zweck/Zuständigkeit: Regulärer n8n-Modus; Zeitpläne und aufrufende Orchestrierung, keine eigene Fachlogik.
- Technologie: n8n, regulärer Modus.
- Daten/Schnittstellen: Nur eigene n8n-Datenbank; Fachjobs über interne APIs.
- Datenbankrollen: n8n_app; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: Versionsabhängiger Readiness-Endpunkt; beim Image-Pinning nachweisen. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-mail-relay

- Zweck/Zuständigkeit: Postfix nimmt Nachrichten von cve-notification an und hält eine persistente Queue.
- Technologie: Postfix.
- Daten/Schnittstellen: Nur festgelegter SMTP-Smarthost über Envoy.
- Datenbankrollen: keine; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_egress_internal. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: interne Ziel-API beziehungsweise SMTP-Proxy.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: SMTP 220, EHLO, QUIT; kein Versand beim Statuscheck. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-api

- Zweck/Zuständigkeit: FastAPI-Gateway: Annahme, Authentifizierung, Autorisierung und expliziter Verwaltungskontext.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Getrennte DB-Pools nach validiertem Authentifizierungskontext.
- Datenbankrollen: api_reader, api_ingest, api_security, dashboard_admin, dashboard_preferences; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-dashboard

- Zweck/Zuständigkeit: Eigenständige Python-Webanwendung: Ansichten und Formulare, serverseitiges Rendering.
- Technologie: Python 3.12; eigenständige Webanwendung.
- Daten/Schnittstellen: API-Aufrufe mit gebundenem menschlichem Sitzungskontext; kein direkter DB-Zugriff.
- Datenbankrollen: keine; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: interne Ziel-API beziehungsweise SMTP-Proxy.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-importer

- Zweck/Zuständigkeit: CVEProject-Originaldaten importieren, validieren und lokal revisionieren.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: CVE-Originaldaten, Quellenstände, Importjobs.
- Datenbankrollen: importer; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data, cve_egress_internal. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-enricher

- Zweck/Zuständigkeit: NVD, CISA KEV, Ubuntu Security und OSV.dev ergänzen.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Quellenspezifische Anreicherungen; keine Überschreibung der Originalquelle.
- Datenbankrollen: enricher; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data, cve_egress_internal. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-inventory

- Zweck/Zuständigkeit: Gemeinsame Verarbeitung validierter Inventare beider Uploadwege.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Snapshots, Software, Dienste, Container; keine administrativen Schreibrechte.
- Datenbankrollen: inventory_processor; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-matcher

- Zweck/Zuständigkeit: Lokale quellenspezifische Betroffenheitsprüfung; neue CVEs lösen neue Auswertung aus.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: CVE-/Inventarleserechte; schreibt nur Matching-Ergebnisse.
- Datenbankrollen: matcher; Details und Verbote gemäß DB-Matrix.
- Netzwerke Phase 17: ausschließlich cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes PostgreSQL, private rollenbezogene Credentials und Namespace-Guard.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-findings

- Zweck/Zuständigkeit: Findings, Risiko und nachvollziehbare Zustandsänderungen verwalten.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Matching-Ergebnisse, Finding-Historie; keine Gruppenschreibrechte.
- Datenbankrollen: findings_writer; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-reporter

- Zweck/Zuständigkeit: Lokale Berichte und Sicherheitskennzahlen erstellen.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Autorisierte Lesesichten und system.reports.
- Datenbankrollen: reporter; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-event-dispatcher

- Zweck/Zuständigkeit: Transactional Outbox mindestens einmal an n8n zustellen.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Outbox-Ereignisse und Zustellmetadaten.
- Datenbankrollen: event_dispatcher; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-notification

- Zweck/Zuständigkeit: Idempotente Benachrichtigungen erzeugen und an Postfix übergeben.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Empfängersichten, Zustellstatus und Benachrichtigungsjobs.
- Datenbankrollen: notification; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## cve-service-status

- Zweck/Zuständigkeit: Auf Anforderung aktuelle direkte Dienstprüfungen durchführen.
- Technologie: Python 3.12; FastAPI.
- Daten/Schnittstellen: Nur SELECT 1; kein Fachdatensatz und keine Docker Engine.
- Datenbankrollen: status_probe; Details und Verbote gemäß DB-Matrix.
- Netzwerke: cve_internal, cve_data. Ausschließlich Wege der Netz-/Trust-Matrix sind erlaubt.
- Betriebsabhängigkeiten: persistentes Volume und rollenbezogene DB-Verbindung.
- Fehler: ungültige Konfiguration verhindert Readiness; Verbindungs-/Timeoutfehler ergeben
  degraded/unreachable, authentifizierte Schreibaufrufe werden nicht stillschweigend verworfen.
- Prüfung: GET /health/live und /health/ready. Liveness beweist nur Prozessantwort, Readiness die erforderlichen
  lokalen Abhängigkeiten; externe Datenquellen sind keine Bedingung für lokale Auswertung.

## Externe Komponenten

| Komponente | Zweck / Daten / erlaubter Weg | Abhängigkeit und Fehlerprüfung |
|---|---|---|
| Ansible-Controller | Manuell erzeugte Dateien an technischen Nginx-Host; HTTPS/mTLS/Token | Kein Hintergrundscan; Uploadfehler sichtbar, Datei lokal behalten |
| CVEProject | Primär-CVE-Daten; importer über Envoy, HTTPS | Quellenstand und letzter erfolgreicher Import; Ausfall lässt lokale Daten lesbar |
| NVD | CVSS/CPE und ergänzende Metadaten; enricher über Envoy | Quoten/429 respektieren, Retry-After und Quellenalter anzeigen |
| CISA KEV | Exploit-Katalog; enricher über Envoy | Revisions-/Freshness-Angabe statt Verfügbarkeitsgarantie |
| Ubuntu Security | Distributionsspezifische Betroffenheit und Backports; enricher über Envoy | Release/Paketzuordnung prüfen, unbekannt bleibt unbekannt |
| OSV.dev | Ecosystem-/Paketinformationen; enricher über Envoy | Fehler oder fehlende Daten schließen kein Finding |
| SMTP-Smarthost | Festes Versandziel; nur Postfix via Envoy TCP | STARTTLS, echte Zielidentität, Authentifizierung; bei Ausfall Queue |

Externe Quellen sind keine zusätzlichen Plattformdienste und erhalten keine internen DB-Rechte.
