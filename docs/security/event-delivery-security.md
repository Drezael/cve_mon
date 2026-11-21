# Sichere Ereigniszustellung

Nur fest registrierte Ziele. Eventpayloads liefern weder URL noch Transportmodul.
Private targets.json (0400/0600, regulär, keine Symlinks) erlaubt maximal 32 eindeutige
Ziele. Jedes bindet ID, HTTPS-Origin mit explizitem cve-*-Docker-Namen, relativen Pfad,
private Token-Datei, CA und begrenzten Timeout. IP-Literale/localhost/Metadata-/freie
Internetziele, URL-Credentials/Queries und Redirects sind abgelehnt. Externe Ziele
benötigen eine spätere ausdrückliche Architektur-/Egressfreigabe, keinen Fallback.

Der Client verwendet HTTPX mit trust_env=False, verifiziertem TLS und deaktivierten
Redirects. Bearer-Credential bleibt in privater Datei/Prozessspeicher und gelangt nie
in Outbox, Payload oder Logs. Fehlende Auth-Dateien verhindern Initialisierung.
Der Receiver muss das Token prüfen; die Zielidentität wird durch CA und DNS-Namen
gebunden. HTTP-2xx ist eine Annahmebestätigung, keine pauschale Fachabschlussgarantie.

Dispatcher nur in cve_data/cve_internal, kein Hostport, Docker-Socket oder NET_ADMIN,
readonly/Nicht-Root/CapDrop ALL. Kein Credential anderer Services im Dispatcher-Mount.
Role event_dispatcher kann Zustellungen bearbeiten, aber keine Gruppen verwalten.
Die tatsächliche n8n-Integration bleibt Phase 19, ohne n8n Queue Mode.
