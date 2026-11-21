# API-Sicherheitsprüfung Phase 23

FastAPI veröffentlicht weiterhin weder docs noch OpenAPI zur Laufzeit. Hostallowlist, private Nginx-Gatewaybindung und bereinigte Proxyheader sind aktiv. Überlange/nicht-ASCII-Portangaben werden ohne Integerkonvertierungsfehler abgewiesen. Alle SQL-Werte bleiben parametrisiert; Sortierfelder sind feste Mappings. DTOs verbieten zusätzliche Properties. Antwortmodelle minimieren Daten.

Die neuen kleinen JSON-Grenzen liefern 400 für mehrdeutige/ungültige Inhalte, 413 bei Übergröße und 415 für ungeeignete Medientypen/Content-Encoding. Inventar-Multipart läuft weiterhin über seinen bestehenden eigenen Ressourcenpfad. Es werden keine Body-/Token-/SQLdetails in Problemantworten ausgegeben. Listen sind begrenzt, Fehler no-store; Nginx plus persistierte Identitätsquoten begrenzen Last. Ein ausgeschöpfter Pool wird nicht mit unbeschränkten Verbindungen oder Retries kaschiert.
