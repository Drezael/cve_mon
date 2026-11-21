# Architektur-Abnahmeszenarien T00.06.04

Diese Szenarien sind Anforderungen an spätere Implementierungen, keine behaupteten Runtime-Tests.
Phase 1 prüft bereits maschinell Verträge/Beispiele und zentrale Strukturinvarianten.
Numerische Folgephasennummern jenseits Phase 2 werden ohne den separaten Gesamtplan nicht erfunden;
angegeben sind die jeweils zuständigen fachlichen Implementierungsphasen.

## SC00-01: Technischer Upload erfolgreich

- Ausgangszustand/Voraussetzungen: Aktiver registrierter Server, gebundenes Zertifikat/Token mit inventory:submit.
- Durchführung: Gültiges JSON an POST /api/v1/inventories, anschließend gleichen Inhalt erneut senden.
- Erwartete API-/Protokollantwort: 202 accepted, dann 200 duplicate.
- Erwartete Datenbankwirkung: Ein Snapshot/Job/Outbox-Ereignis; zwei trusted Receipts.
- Nicht zulässige Nebenwirkungen: Keine Registrierung oder organisatorische Änderung.
- Spätere Implementierungsphase: API/Inventar.

## SC00-02: Technischer Upload ohne mTLS

- Ausgangszustand/Voraussetzungen: Aktiver Server und gültiger Token, aber kein gültiges Clientzertifikat.
- Durchführung: HTTPS-Upload ohne Zertifikat, mit abgelaufenem Zertifikat und gefälschtem Zertifikatsheader versuchen.
- Erwartete API-/Protokollantwort: TLS-Ablehnung vor Fachrequest, kein Erfolg durch Header.
- Erwartete Datenbankwirkung: Keine Annahme/Fachänderung; sanitierte Sicherheitsprotokollierung.
- Nicht zulässige Nebenwirkungen: Kein alternativer Token-only-Weg.
- Spätere Implementierungsphase: Ingress/API.

## SC00-03: Technischer Upload mit ungültigem Token

- Ausgangszustand/Voraussetzungen: mTLS gültig, Token widerrufen/abgelaufen oder fremder Principal.
- Durchführung: POST des gültigen Inventars mit falschem Token.
- Erwartete API-/Protokollantwort: 401, bei gültiger Identität ohne Scope 403; fremde Server-ID 404.
- Erwartete Datenbankwirkung: Kein Snapshot/Job.
- Nicht zulässige Nebenwirkungen: Kein Zugriff auf Admin-Endpunkte.
- Spätere Implementierungsphase: API/Sicherheit.

## SC00-04: Dashboard-Datei-Upload erfolgreich

- Ausgangszustand/Voraussetzungen: Angemeldeter berechtigter Benutzer und passender CSRF-Token.
- Durchführung: Multipart file plus identische server_id an Dashboard-Upload senden.
- Erwartete API-/Protokollantwort: 202 accepted; trusted source dashboard_file.
- Erwartete Datenbankwirkung: Gleiche Snapshot-/Jobform wie technischer Weg, Herkunft Receipt.
- Nicht zulässige Nebenwirkungen: Kein mTLS-Zwang für diesen menschlichen Weg, keine Gruppenänderung.
- Spätere Implementierungsphase: Dashboard/Inventar.

## SC00-05: Dashboard-Upload ohne Sitzung

- Ausgangszustand/Voraussetzungen: Gültige Datei und bekannte Ziel-ID, keine Sitzung.
- Durchführung: Datei ohne Session-Cookie hochladen.
- Erwartete API-/Protokollantwort: 401.
- Erwartete Datenbankwirkung: Keine Annahme.
- Nicht zulässige Nebenwirkungen: Kein Fallback auf technischen Upload-Token.
- Spätere Implementierungsphase: Dashboard/Sicherheit.

## SC00-06: Dashboard-Upload ohne CSRF

- Ausgangszustand/Voraussetzungen: Gültige Sitzung mit Uploadrecht.
- Durchführung: CSRF entfernen/verfälschen und fremde Origin senden.
- Erwartete API-/Protokollantwort: 403.
- Erwartete Datenbankwirkung: Keine Annahme/Job.
- Nicht zulässige Nebenwirkungen: SameSite allein gilt nicht als bestandener Schutz.
- Spätere Implementierungsphase: Dashboard/Sicherheit.

## SC00-07: Unbekannter Server

- Ausgangszustand/Voraussetzungen: Gültige Upload-Identität; UUID ist nicht registriert.
- Durchführung: Inventar mit neuer unbekannter server_id senden.
- Erwartete API-/Protokollantwort: 404 server_not_found.
- Erwartete Datenbankwirkung: Keine servers-/snapshot-/group-Anlage.
- Nicht zulässige Nebenwirkungen: Keine automatische Registrierung.
- Spätere Implementierungsphase: API/Inventar.

## SC00-08: Nicht autorisierter Server

- Ausgangszustand/Voraussetzungen: Benutzer/Principal hat nur Server A, Datei verweist auf B.
- Durchführung: Upload und lesenden Detailzugriff für B versuchen.
- Erwartete API-/Protokollantwort: 404 ohne Existenzoffenlegung; fehlender Aktionsscope 403.
- Erwartete Datenbankwirkung: Keine Annahme für B.
- Nicht zulässige Nebenwirkungen: Kein Zugriff durch manipulierte group_ids.
- Spätere Implementierungsphase: Autorisierung.

## SC00-09: Gruppierungsfelder im Upload

- Ausgangszustand/Voraussetzungen: Gültiges Beispielinventar.
- Durchführung: group_id, group_ids, primary_group_id, group_sort_order und display_order jeweils oben und in verschachtelten Objekten ergänzen.
- Erwartete API-/Protokollantwort: 422 invalid_inventory.
- Erwartete Datenbankwirkung: Keine Annahme und keine Verwaltungsänderung.
- Nicht zulässige Nebenwirkungen: Unbekannte Metadaten-Bags dürfen Felder nicht verstecken.
- Spätere Implementierungsphase: Verträge/Inventar.

## SC00-10: Upload lässt administrative Daten unverändert

- Ausgangszustand/Voraussetzungen: Server besitzt mehrere Gruppen, Primärgruppe und gespeicherte Positionen.
- Durchführung: Gültige complete/partial/failed-Inventare über beide Wege verarbeiten.
- Erwartete API-/Protokollantwort: 202 beziehungsweise 200 bei Duplikat.
- Erwartete Datenbankwirkung: Nur Inventar-/Software-/Jobdaten ändern; Vergleich der Adminzeilen identisch.
- Nicht zulässige Nebenwirkungen: Keine Serverstammdaten-/Gruppen-/Sortieränderung und keine entsprechenden DB-Grants.
- Spätere Implementierungsphase: Inventar/Datenbank.

## SC00-11: Gruppenänderung im Dashboard

- Ausgangszustand/Voraussetzungen: MFA-verifizierter Administrator, If-Match aktuell.
- Durchführung: Mitgliedschaften/Primärgruppe per /dashboard/admin/servers/{server_id}/groups ersetzen; parallel stale ETag verwenden.
- Erwartete API-/Protokollantwort: 200 mit neuer Version; stale 412, fehlender ETag 428.
- Erwartete Datenbankwirkung: FK-gültige Mitgliedschaft plus Audit atomar.
- Nicht zulässige Nebenwirkungen: Keine ungültige Primärgruppe und keine Inventaränderung.
- Spätere Implementierungsphase: Verwaltung/Datenbank.

## SC00-12: Manuelle Sortieränderung

- Ausgangszustand/Voraussetzungen: Aktueller Sortier-ETag und globale groups:manage-Berechtigung.
- Durchführung: Eindeutige vollständige Permutation senden; dann doppelte/fremde/veraltete IDs versuchen.
- Erwartete API-/Protokollantwort: 200 für gültige Reihenfolge, 409/412/404 für Konflikt/unsichtbares Objekt.
- Erwartete Datenbankwirkung: Nur dashboard.order-Zeilen, Version und Audit.
- Nicht zulässige Nebenwirkungen: Kein Reordering durch Inventory-/Matching-Job.
- Spätere Implementierungsphase: Dashboard/Verwaltung.

## SC00-13: Upload-Token kann Gruppen nicht verwalten

- Ausgangszustand/Voraussetzungen: Gültiger technischer Token mit Serverzugriff.
- Durchführung: PATCH/PUT auf /dashboard/admin-Operationen mit Bearer statt Sitzung.
- Erwartete API-/Protokollantwort: 401; technischer Nginx-Host routet diese Pfade gar nicht (404).
- Erwartete Datenbankwirkung: Keine Adminänderung.
- Nicht zulässige Nebenwirkungen: Ein gültiger technischer Token ist keine menschliche Sitzung.
- Spätere Implementierungsphase: API/Sicherheit.

## SC00-14: Kein Gruppenwechsel nach Matching

- Ausgangszustand/Voraussetzungen: Serverorganisation und Positionswerte vorab festgehalten.
- Durchführung: matching.run, findings.reconcile und zugehörige n8n-Events ausführen.
- Erwartete API-/Protokollantwort: Interne Jobannahme 202, Ergebnis abfragbar.
- Erwartete Datenbankwirkung: Matching/Findings/Outbox ändern, organisatorische Zeilen unverändert.
- Nicht zulässige Nebenwirkungen: Kein eventbasierter Gruppenbefehl.
- Spätere Implementierungsphase: Matching/n8n.

## SC00-15: Neue CVE ohne neuen Upload

- Ausgangszustand/Voraussetzungen: Vollständiger lokaler Snapshot und bereits ausgewerteter Quellenstand.
- Durchführung: Neue CVE-Revision importieren und cve.updated zustellen.
- Erwartete API-/Protokollantwort: Jobannahme 202; neues Matching/Finding abfragbar.
- Erwartete Datenbankwirkung: Neue Bewertung auf bestehendem inventory_id.
- Nicht zulässige Nebenwirkungen: Kein erzwungenes Ansible-Submit und keine Quellenabfrage aus Matcher.
- Spätere Implementierungsphase: Import/Matching.

## SC00-16: Ubuntu-Backport

- Ausgangszustand/Voraussetzungen: Synthetischer Ubuntu-Release/Paketstand mit Hersteller-fix und abweichendem Upstreambereich.
- Durchführung: Epoch/Distributionsrevision erhalten und quellenspezifisch bewerten; unklare Quelle zusätzlich simulieren.
- Erwartete API-/Protokollantwort: Lesbares not_affected mit Hersteller-/Regelreferenz beziehungsweise unknown.
- Erwartete Datenbankwirkung: Reproduzierbare Matching-Evidenz, keine unbegründete Schließung.
- Nicht zulässige Nebenwirkungen: Kein lexikographischer/upstream-only Versionsvergleich.
- Spätere Implementierungsphase: Enrichment/Matching.

## SC00-17: Offline-Matching

- Ausgangszustand/Voraussetzungen: Quellenrevisionen, Inventare und Benutzer lokal vorhanden; Internet/Envoy blockiert.
- Durchführung: CVE-Suche, Login, Inventory-Lesen und Matching anfordern.
- Erwartete API-/Protokollantwort: Lokale Funktionen erfolgreich; Aktualitätswarnung statt externer Pflichtverbindung.
- Erwartete Datenbankwirkung: Neue lokale Ergebnisse möglich, Quellenstände unverändert.
- Nicht zulässige Nebenwirkungen: Kein direkter Internet-Fallback, keine False-safe-Bewertung.
- Spätere Implementierungsphase: Matching/Betrieb.

## SC00-18: Postfix-Queue bei externem Ausfall

- Ausgangszustand/Voraussetzungen: Notification darf an Postfix senden, Smarthost/Envoy nicht erreichbar.
- Durchführung: Mail einliefern, Postfix neu starten, Verbindung wiederherstellen; falsches TLS-Zertifikat testen.
- Erwartete API-/Protokollantwort: Interne SMTP-Annahme möglich; kein garantierter delivered-Status; TLS-Namensfehler bleibt Fehler.
- Erwartete Datenbankwirkung: Persistente Queue, Retry und begrenzte Laufzeit, Zustellstatus nachvollziehbar.
- Nicht zulässige Nebenwirkungen: Keine verlorene Queue, kein unverschlüsselter Fallback/Open Relay.
- Spätere Implementierungsphase: SMTP/Infrastruktur.

## SC00-19: Statuspage mit ausgefallenem Dienst

- Ausgangszustand/Voraussetzungen: Gültige Sitzung mit deployment:status:read, ein Ziel antwortet nicht.
- Durchführung: GET Status zweimal aufrufen und tatsächliche neue Zielaufrufe zählen.
- Erwartete API-/Protokollantwort: 200 overall degraded mit neuem checked_at, Ziel unreachable; API-/Statusausfall 503.
- Erwartete Datenbankwirkung: Keine fachliche DB-Änderung, maximal SELECT 1.
- Nicht zulässige Nebenwirkungen: Kein Cache als live, keine freien Zielparameter, Gesamtbudget einhalten.
- Spätere Implementierungsphase: Statuspage.

## SC00-20: Statuspage ohne Docker Engine

- Ausgangszustand/Voraussetzungen: Statuscontainer ohne Socket, Host-Bridge oder Docker-Rechte.
- Durchführung: Alle festen Protokollchecks ausführen und Prozess-/Netzrechte inspizieren.
- Erwartete API-/Protokollantwort: Statusresultate allein aus direkten Dienstprüfungen.
- Erwartete Datenbankwirkung: Keine Docker-/Host-/Containersteuerung.
- Nicht zulässige Nebenwirkungen: Keine Engine-API, kein Containerrestart, keine beliebige Probe-URL.
- Spätere Implementierungsphase: Statuspage/Infrastruktur.

## SC00-21: Anmeldung und MFA

- Ausgangszustand/Voraussetzungen: Aktives Admin-Konto mit bestätigter TOTP-Methode.
- Durchführung: Login, Zugriff vor MFA, korrekter/falscher/wiederholter TOTP, Logout und Session-Replay testen.
- Erwartete API-/Protokollantwort: Login mfa_required; vor MFA kein Fachzugriff; nach korrekter MFA Sitzung; Replay/falscher Code abgelehnt; nach Logout 401.
- Erwartete Datenbankwirkung: Challenge verbraucht, Sessionverifikator geschützt, last_used_step und Audit korrekt.
- Nicht zulässige Nebenwirkungen: Keine Ausgabe von Hash/Seed und keine vollwertige Sitzung vor MFA.
- Spätere Implementierungsphase: Authentifizierung.

## SC00-22: Letzter aktiver Administrator

- Ausgangszustand/Voraussetzungen: Zwei Administratoren oder nur ein letzter aktiver Admin, getrennte konkurrierende Sitzungen.
- Durchführung: Parallel Rollen entziehen, sperren, deaktivieren, archivieren oder MFA entfernen.
- Erwartete API-/Protokollantwort: Mindestens eine unzulässige Änderung 409 last_active_admin; zulässiger Wechsel atomar.
- Erwartete Datenbankwirkung: Invariantensperre verhindert null aktive MFA-fähige Administratoren.
- Nicht zulässige Nebenwirkungen: Kein Aussperren durch Race Condition oder Selbstprivilegierung.
- Spätere Implementierungsphase: Benutzerverwaltung/Datenbank.
