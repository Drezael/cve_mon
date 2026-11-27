# Envoy ab Phase 4


> Seit der Zusammenfassung auf sieben Dienste verwendet der Anwendungsstack direkte
> HTTPS- und SMTP-Verbindungen. Die folgenden Envoy-Betriebshinweise beschreiben
> den früheren Proxybetrieb. Der erhaltene Policygenerator wird ausschließlich im
> isolierten Kompatibilitätslabor unter `tests/infrastructure/envoy` geprüft;
> der Standardstart lädt keinen Envoydienst.

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Offizielles gepinntes Envoy 1.40.2, HTTP/CONNECT 3128, SMTP-TCP 1587, geschütztes Health 9901.
Die versionierte Gesamtdatei envoy.yaml ist die geschlossene Auslieferung ohne Clientbindungen.
Der Operator rendert genau eine vollständige v3-Datei aus der strikten Policy und geprüften
aktuellen Clientendpoints; keine nicht unterstützten YAML-Includes und keine zweite Proxylogik.

Einstieg: make envoy-policy-check, envoy-check, envoy-up, envoy-test, envoy-down.
Betrieb und Sicherheitsnachweis unter docs/deployment/envoy.md und docs/development/phase-04-acceptance.md.
