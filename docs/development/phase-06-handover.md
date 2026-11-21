# Phase-6-Übergabe

Phase 7 erhält installierbare Pakete 0.6.0, kontrollierte Worker-Ressourcen,
Database/DatabaseRegistry, unabhängige Sessions und explizite Transaktionen,
Task-lokale Request-/Korrelations-IDs und JSON-Fehler-/Logstandards.
Fachänderung und späteres Outbox-Ereignis können dieselbe Transaktion nutzen.
Jobs und Outbox sind hier bewusst nicht verarbeitet.

Phasen 8–11 ergänzen Authentifizierung, ausdrücklich autorisierte DB-Kontexte und
Fachrouter; API in dieser Phase nur api_reader und technische Health. mTLS-Upload-
Identität muss später selbst sicher gebunden werden; keine Header-Scheinauthentifizierung.
Phasen 14–19 aktivieren Worker mit eigenen Rollen/Netzen und externem HTTP nur über
Envoy. Notification verwendet Postfix, keine Python-Mailqueue. Dashboard 20–21 hat
keinen direkten DB-Zugriff, Statusmonitor 22 verwendet Protokollprüfungen ohne Docker-API.

[Basis](../architecture/python-services.md), [Konfiguration](../security/service-configuration.md),
[Betrieb](../deployment/python-services.md), [Tests](../testing/phase-06-test-matrix.md).
