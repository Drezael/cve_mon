# Ingress-Sicherheitsgrenzen

Nur Nginx veröffentlicht HTTP/HTTPS; Phase 2 liefert ausschließlich Fehler-/Healthantworten,
keine APIs als unfertige Erfolge. Routinggrenzen und alle Statuscodes stehen in
[nginx.md](../deployment/nginx.md). HTTP akzeptiert keine Uploads, unbekannte Hosts führen
nicht zu beliebigen Redirects, unbekanntes TLS-SNI wird beim Handshake verworfen.

Client-IP für Limits ist ausschließlich der TCP-Peer, niemals ein vom Internet behaupteter
X-Forwarded-For-Wert. Request-ID wird neu erzeugt. Host/SNI werden als Paar geprüft.
Zertifikats-/Forwarded-Identitätsheader werden in vorbereiteten Proxy-Snippets entfernt;
kein Backend ist aktiviert, daher wird heute auch kein Identitätsheader weitergeleitet.

Rate-Limits sind pro Peer-IP getrennt für Web und Uploads. Spätere Principal-/Kontolimits
bleiben Aufgabe der authentifizierten API, Nginx-IP-Limits ersetzen sie nicht.
Größenlimits 10 MiB JSON / 11 MiB Multipart, begrenzte Verbindungen und Header-/Body-/Sendzeiten.
Die aktuelle Phase nimmt keine Bodies fachlich an; deklarierte Übergröße liefert 413,
zu hohe Frequenz 429, fehlende Backends 503. Limits greifen vor dem Contenthandler.

HTTPS-Fehlerantworten tragen zentrale Header genau einmal. Keine lange HSTS-Speicherung in
Entwicklung, restriktive CSP bis zur kontrollierten Dashboardintegration. Kein offener Proxy,
keine WebSocket-Weiterleitung vor Integration. Später benötigt n8n eine explizite WebSocket-
Route mit erlaubtem Upgrade und vertrauenswürdigen Proxy-Headern; keine pauschalen Hop-by-Hop-Header.
