# ASVS- und SSDF-Zuordnung Phase 23

Grundlage ist [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0). Die Kapitel-/Kontrollkennungen wurden gegen die offizielle versionierte JSON-Datei geprüft. Diese risikobasierte Auswahl ist keine vollständige ASVS-Konformitäts- oder Zertifizierungsbehauptung. Die zugehörige lokale 137-Punkte-Matrix steht unter testing/phase-23-security-matrix.md. Interne lokale HTTP-Healthsignale sind ausdrücklich keine durchgängige mTLS-Architektur.

| Kapitel | Verifizierte Referenzkennungen (Auswahl) | Umsetzung/Anwendbarkeit | Nachweis |
|---|---|---|---|
| V1 | V1.1.1, V1.2.1 | cve_api/auth/json_boundary; Inventarparser; React-Ausgabe; parametrisierte SQL-Werte | phase-23-api/uploads/pipelines/frontend |
| V2 | V2.1.1, V2.2.1 | geschlossene Payloadmodelle, feste Sortierungen, Schema-/Eingabegrenzen | phase-23-api/uploads/pipelines |
| V3 | V3.1.1, V3.2.1 | HTTPS/CSP/no-store, gleiche Origin, kein Tokenstorage | phase-23-containers/frontend |
| V4 | V4.1.1, V4.2.1 | HTTP-Grenzen, Medientypen, Gateway/Host-/Proxyprüfung | phase-23-api/containers/uploads |
| V5 | V5.1.1, V5.2.1 | 10-MiB-Schema, Prozess-/Zeitgrenzen, keine freie Dateiausführung | phase-23-uploads/hardening |
| V6 | V6.1.1, V6.2.1 | Argon2, TOTP, aktuelle Benutzer-/Credentialversion, persistierte Rate-Limits | phase-23-auth |
| V7 | V7.1.1, V7.2.1 | serverseitige opake Sitzung, absolute/idle Fristen, Rotation/Widerruf | phase-23-auth |
| V8 | V8.1.1, V8.2.1 | Funktionsrecht plus Server-ACL vor Counts/Seiten; kein Rechtecache | phase-23-rbac/frontend |
| V9 | V9.1.1, V9.2.1 | bedingt: signierte interne Callbacknachweise; Browsersitzungen/Uploadtokens sind opak | phase-23-pipelines; keine allgemeine JWT-/Stateless-Token-Konformität |
| V10 | V10.1.1, V10.2.1 | nicht anwendbar: keine OAuth-/OIDC-Anmeldung implementiert | Architektur-/Authreview |
| V11 | V11.1.1, V11.2.1 | vorhandene Kryptographiebibliotheken, Key-ID/Lifecycle und AES-GCM-Backupumschlag | phase-23-auth/hardening/recovery |
| V12 | V12.1.1, V12.2.1 | TLS1.2/1.3, verify-full und kein Zertifikatsfallback für externe/persistente Zugriffe | phase-23-containers/networks/uploads |
| V13 | V13.1.1, V13.2.1 | 13-Dienste-Modell, minimale Ports/Mounts/Capabilities, feste interne Identitäten | phase-23-containers/networks/database |
| V14 | V14.1.1, V14.2.1 | Verifikatoren, minimierte DTOs/Logs, keine Secrets in URLs/Artefakten | phase-23-api/uploads/pipelines; security-secrets |
| V15 | V15.1.1, V15.2.1 | Source-/Lock-/Imageinventar, SBOM, Tests; Imagebefunde offen und blockierend | phase-23-supply-chain; NO_GO |
| V16 | V16.1.1, V16.2.1 | strukturierte minimierte Logs, Korrelation, unveränderliches Audit, sichere Problemantworten | phase-23-auth/database/pipelines/resilience |
| V17 | V17.1.1, V17.2.1 | nicht anwendbar: kein WebRTC/TURN/DTLS-Endpunkt | Architekturreview |

OWASP API Top 10 (2023): API1/API3/API5 → Objekt-/Property-/Funktionsgrenzen; API2 → Auth/MFA/Sessions; API4/API6 → Request-/Parser-/Rate-/Concurrencygrenzen; API7 → feste Egressziele; API8 → Compose/TLS/DB-Konfiguration; API9 → Router-/Artefaktinventar; API10 → begrenzte externe Parser/Provenienz. [Offizielle Grundlage](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

[NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final): PO → Architektur/Verantwortung/Budgets und Prüfplan; PS → Quellhashes, gepinnte Werkzeuge/Locks, getrennte Secrets und Backupnachweis; PW → Threat Model, sichere Eingaben, Review und Negativ-/Integrations-/Lasttests; RV → priorisierte Einzelbefunde, blockierende Gates und konkrete Update-/Incidentverfahren. Kein signierter Buildprovenienz- oder formaler SSDF-Zertifizierungsnachweis wird behauptet.
