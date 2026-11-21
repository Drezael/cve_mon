# Sicherheit administrativer Oberflächen

Vorhandene Cookie-/Same-Origin-/CSRF-/MFA-/ACL-Grenzen bleiben maßgeblich. Keine neue
Autorisierungslogik, keine technischen Tokens im Browser und keine Datenbank-/SSH-/Worker-
Verbindung. Kontrollierte Endpunkte, explizite Feldlisten, eingefangene Versionen und
serverseitiger letzter-Administrator-Schutz. Keine Optimistic-Success-Anzeige und kein
automatischer Write-Retry. CSP aus Phase 20 bleibt ohne unsafe-inline/unsafe-eval wirksam.

Für bestehende maximale ACL-/Vorlagen-/Regelverträge sind nur die exakt freigegebenen
Server-ACL-, Notification-Regel-/Vorlagen- und Previewpfade bis 32768 Bytes zugelassen.
Alle übrigen Auth-/Dashboard-/Finding-JSON-Anfragen behalten 8192 Bytes; Login- und
MFA-Grenzen bleiben unverändert. Nginx und AuthBoundary begrenzen vor Pydantic. Der
bestehende separat begrenzte Multipart-Uploadweg bleibt unverändert. Zu große Requests
werden weiterhin 413; passende Grenztests sind Teil von Phase 21.

Keine neuen menschlichen Permissions. Die additive Migration 00029 enthält ausschließlich
Lesesicht/-grants, keine Domain-DML. Hintergrundtests laufen in isolierten Projekten;
normale Regeln, Mailfreigaben, Quell-/Inventar-/Finding-Daten und fremde Container bleiben
unverändert. Keine fremden Geheimnisse in Formularen, Preview, Logs oder Auditansichten.
