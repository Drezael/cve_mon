# mTLS-Vertrauensgrenze

Eigenes bestehendes INVENTORY_DOMAIN, ssl_verify_client on, ssl_verify_depth 2 und ssl_crl.
Kein neuer Hostport. API-Domain nimmt keine Inventare an; technischer Host bietet weder
Browserlogin noch Dashboardadministration. Kette, Gültigkeit und clientAuth werden im TLS-
Kontext geprüft. Tests decken fehlende, fremde, abgelaufene, widerrufene und falsche EKU ab.

Nginx überschreibt X-CVE-Inventory-Gateway/Scheme/Verify/Certificate vollständig. Verify
stammt aus ssl_client_verify, Certificate aus ssl_client_escaped_cert. Private Capability
liegt nur in eigenen geschützten API-/Nginx-Mounts. Direkter interner Aufruf ohne Capability
wird abgelehnt; bloße Zertifikats-/Benutzerheader sind kein Nachweis. Backend prüft exakten
Host, Scheme, Header-Eindeutigkeit und aktuelle CRL; fingerprint ist SHA-256 des DER-Zertifikats,
kein langfristiger SHA-1-Header. Keine Zertifikatsinhalte in Access-/Anwendungslogs.

Der aktuelle Trustvertrag verwendet eine ausdrücklich konfigurierte Client-Aussteller-CA
mit ihrer signierten gültigen CRL. Ein anderer Aussteller benötigt seine passende CRL;
fehlende/abgelaufene/ungültige Sperrlisten führen geschlossen zum Fehler. Öffentliche CA/CRL
werden in den API-Mount kopiert, niemals CA- oder Client-Privatschlüssel. Eigene Test-PKI ist
lokal, nicht produktiv. Betreiber ersetzen CLIENT_CA_FILE/CLIENT_CRL_FILE kontrolliert und
führen nginx-check/infra-reload aus. PKI-Prüfung gehört zur API-Readiness.
