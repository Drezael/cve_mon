# Analyse Phase 20

Ausgangsbasis: API 0.19.0, Head 00027 und dreizehn eigene Dienste. Dashboard bisher
lediglich Nginx-503-Platzhalter; kein bestehendes Frontend-Framework. Auth, MFA, CSRF,
Sessioncookies, Permissions und Objekt-ACL existieren. Server/Gruppen, Findings und
Notifications liefern bereits geschützte Lese-Endpunkte. Es fehlen die Benutzeroberfläche,
aggregierte Kennzahlen/UTC-Zeitreihen und eine minimierte aktuelle Inventarzusammenfassung.

Statisches React/TypeScript mit Vite; Node ausschließlich als Build-/Testwerkzeug. Keine
zusätzlichen Produktivcontainer oder Datenbanken. Dashboard-Host und Same-Origin-API bleiben
verbindlich. Bestehende Viewer-Rechte enthalten kein security:overview:read; deshalb ist
für Viewer die Serverliste der Einstieg. Es werden keine impliziten Rechte hinzugefügt.

Datenfrische verwendet ausschließlich die genehmigte Finding-Policy. Ohne Altersgrenze
heißt der Zustand nicht konfiguriert, niemals automatisch aktuell. Letzter Versuch und
letzter gültiger Snapshot bleiben getrennt. Risiko, Matching-Status und Lifecycle werden
nicht vom Frontend neu berechnet. Keine Phase-21-Verwaltungsdialoge.
