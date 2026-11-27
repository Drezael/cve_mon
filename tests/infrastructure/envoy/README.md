# Isolierter Envoy-Kompatibilitätstest

Die Anwendung verwendet direkte HTTPS-Verbindungen und einen direkten
Postfix-Smarthost. Kein Envoydienst gehört zum regulären sieben Dienste
umfassenden Compose-Modell.

Die vorhandene Policygenerator-Bibliothek wird weiterhin mit echten
HTTP-/CONNECT-/DNS-/TCP- und Namespaceprüfungen in einem getrennten Labor getestet.
Nur dessen Fixture lädt [compose.yml](compose.yml). Diese Definition öffnet keinen
Hostport, erweitert keine Anwendungsfreigaben und wird von `cve_mon start` nicht
geladen. Fehler vor dem Fixture-`yield` bauen eigene Ressourcen über registrierte,
labelgeprüfte Aufräumfunktionen ab. Fremde Labore bleiben bestehen.

Aktuelle Anwendungsgrenzen prüfen `tests/application`, die Containerfälle in
`tests/cve_importer` und `tests/cve_enricher`, die Worker-/API-Suiten sowie
`tests/infrastructure/mail` über ihren direkten Pfad.
