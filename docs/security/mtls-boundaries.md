# mTLS- und Uploadgrenzen

inventory.example.test als Entwicklungsbeispiel verlangt ssl_verify_client on,
autorisierte Client-CA und begrenzte Verifikationstiefe. Fehlende, fremd signierte und
abgelaufene Zertifikate werden tatsächlich abgewiesen. Ein gültiger Client erhält nur 503.
Dashboard/API/n8n verlangen kein technisches Clientzertifikat, administrative Routen bleiben 403.

Gefälschte Verifikations-/Zertifikats-/IP-Header ersetzen kein Clientzertifikat. In Phase 2
existiert kein aktiver Backendproxy, daher wird keine frei behauptete Zertifikatsidentität
an eine Anwendung übergeben. proxy-headers.conf ist ausschließlich vorbereiteter Vertrag:
Host/Schema/Peer-IP/Request-ID kontrolliert setzen, Forwarded und Client-Identitätsheader entfernen.

Spätere Phase 8/11 muss dedizierten authentifizierten Nginx→API-Kanal und gültige Peerbindung
nachweisen. Verifizierte Zertifikatsidentität, technischer Token und erlaubte server_id müssen
zusammenpassen; ein Header allein ist niemals hinreichend. Clientzertifikat nicht unnötig
vollständig weiterreichen. Token-/Objektprüfung, Widerruf und Normalisierung werden nicht
als bereits implementiert behauptet.

Dashboard-Datei-Upload bleibt gleicher Browser-Origin, später Sitzung plus CSRF und Serverrecht;
kein technisches mTLS und keine Gruppenoperation. Alle Gruppen-/Sortieraktionen bleiben im
späteren menschlichen Verwaltungsbereich. [Vertrag](../../contracts/api/openapi.yaml).
