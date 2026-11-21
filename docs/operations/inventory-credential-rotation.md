# Credentials kontrolliert verwalten

Dashboard-Admin mit MFA, CSRF und frischer Einmal-Reauth; Permission server:acl:manage.
POST admin/inventory-clients mit begrenztem Namen; POST clients/{id}/certificates mit
öffentlichem certificate_pem/optionalem chain_pem. Niemals private Schlüssel hochladen.
POST clients/{id}/tokens mit server_id, certificate_id und expires_at. Klartexttoken wird
nur jetzt ausgegeben; sofort unabhängig geschützt übergeben, nicht in Chat/Logs kopieren.
Listen liefern ausschließlich Metadaten, keinen Wiederabruf des Tokens.

POST inventory-tokens/{id}/rotate mit Grund, neuem Ablauf und optional neuer Zertifikats-ID
widerruft den alten Token atomar. Server bleibt derselbe. Zertifikatsrotation: neues öffentliches
Zertifikat prüfen/registrieren, servergebundene Tokens ausdrücklich rotieren, Übergang testen,
altes Zertifikat mit inventory-certificates/{id}/revoke sperren. Dies widerruft auch gebundene
Tokens. Client /disable blockiert alle seine Tokens; /enable stellt keine gesperrten Zertifikate
oder Tokens wieder her. Token /disable beziehungsweise /revoke benötigt ebenfalls Reauth.

CLIENT_CRL_FILE muss aktuell und von der konfigurierten Aussteller-CA signiert sein. Lokale
Entwicklung darf eine fehlende CRL aus der markierten Test-PKI erzeugen; Produktion verlangt
extern bereitgestellte öffentliche CA/CRL. Die lokale CRL läuft nach sieben Tagen ab, bewusst
kein unbeaufsichtigtes PKI-Renewal. Vor Ablauf Betreiberaktualisierung durchführen, öffentliche
Snapshots über api-prepare/infra-reload aktualisieren und mTLS-Prüfungen wiederholen. Eine
abgelaufene CRL wird nie als gültiger Fallback behandelt.
