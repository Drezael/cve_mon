# Technische Upload-Credentials

Seit Schema 1.2 und Migration `00041_server_discovery` gilt der vereinfachte
[Onboarding-Ablauf](../operations/server-onboarding.md): Upload ohne Vorabregistrierung,
automatische Serveranlage und wiederverwendbare Collector-Zugänge. Die folgenden
Abschnitte beschreiben den erhaltenen ursprünglichen Uploadvertrag.


Bestehende technical_principals/api_tokens/principal_server_access werden wiederverwendet;
technical_certificates ergänzt öffentliche PEM, DER-SHA-256, Gültigkeit, Erteiler und Widerruf.
Private Schlüssel werden schon syntaktisch abgelehnt. Zertifikatsregistrierung prüft Trustkette,
clientAuth, Datum und Sperrliste. Fingerprints sind global eindeutig, keine Umregistrierung
eines alten Zertifikats unter anderer Clientidentität.

Ein Token ist UUID + 32 zufällige Bytes in URL-safe Base64. In PostgreSQL liegt ausschließlich
ein HMAC-SHA-256-Verifikator mit privatem API-Schlüssel. Genau ein Client, Zertifikat, Server
und inventory:submit; keine frei übermittelbaren Scopes. Ausgabe nur einmal bei Erstellung/
Rotation, nie bei Listen/Widerruf. Laufzeit mindestens fünf Minuten, höchstens 90 Tage und
höchstens bis Zertifikatsablauf. Metadaten zeigen Status, Ablauf, Widerruf und letzte Nutzung.

Verwaltung nutzt bestehendes nicht delegierbares server:acl:manage mit vollständiger
Administrator-MFA, Origin/CSRF und aktueller einmaliger Reauth. User Admin/Analyst/Viewer
haben keine Credentialverwaltung. api_ingest darf weder Tokens/Certificates lesen noch
ändern; eine begrenzte Security-Definer-Funktion prüft Verifikator und Bindung ohne Hash-
Offenlegung. Alle Änderungen werden auditiert. Tokenrotation widerruft den alten Token
atomar und erweitert nie den Serverbereich. Client-Deaktivierung und Certificatewiderruf
werden auch bei laufenden Uploads vor Commit wirksam. Legacy-runtime_version=0 gilt nicht
an der neuen technischen API. Keine dynamische Datenbankrollenwahl.
