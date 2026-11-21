# Infrastruktur

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Phase 2 implementiert ausschließlich Nginx mit Docker Compose und fünf Netzwerkdefinitionen.
[Einrichtung](../docs/deployment/docker-compose.md), [Sicherheitsgrenzen](../docs/security/network-isolation.md).
PostgreSQL, Envoy, Postfix, n8n und Fachdienste bleiben spätere Phasen.
