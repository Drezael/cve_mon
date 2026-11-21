# Nginx Phase 2

> Aktueller Betrieb: unveränderte Docker-Hub-Images gemäß `infrastructure/images.lock.json`. Frühere Hinweise auf eigene Hersteller-Builds/Paketentfernung sind historisch und durch die Umstellung auf Original-Images ersetzt. Es werden keine Herstellerprogramme nachgepatcht.


Offizielles, versioniertes und digestgepinntes Nginx. nginx.conf lädt ausschließlich das
kontrollierte .runtime-Projektsnapshot unter /etc/nginx/cve, keine Basisimage-Standardwebsite.
Templates/konstante Snippets sind versioniert, generierte Konfiguration/PKI ignoriert.
[Konfiguration](../../docs/deployment/nginx.md), [Einrichtung](../../docs/deployment/docker-compose.md),
[TLS](../../docs/deployment/tls-certificates.md), [Abnahme](../../docs/development/phase-02-acceptance.md).
