# Offene technische Nachweise und Abgleichpunkte

Diese Punkte sind keine ungelösten Widersprüche der verfügbaren Architekturvorgaben.
Phase 0 spezifiziert Verträge; tatsächliche Softwareintegration erfolgt in Folgephasen.

| ID | Punkt | Zuständiger Folgeschritt / Abnahmekriterium |
|---|---|---|
| OP00.01 | Gesamtkonzept 3.12 und Entwicklungsplan 1.2 fehlen als separate Originale | Vor Folgeimplementierung mit verfügbaren Phasenkonzepten abgleichen; keine erfundenen numerischen Zuordnungen für unbekannte Folgephasen |
| OP00.02 | Konkrete Domains, PKI, Widerrufsverfahren, Zertifikats-/Secretbereitstellung | Phase 2: Ende-zu-Ende-TLS, Pflicht-mTLS und manipulierbare Header testen |
| OP00.03 | Envoy-Version und server-first TCP-Verhalten, Rebinding-/IPv6-Filter | Infrastrukturphase: gepinnte Konfiguration, echte erlaubte/verbotene Verbindungen |
| OP00.04 | Postfix-TLS-Policy mit internem Nexthop und externer Smarthost-Identität | SMTP-Phase: Zertifikats-Namensfehler/fehlendes STARTTLS/AUTH-Ausfall müssen fehlschlagen |
| OP00.05 | n8n-Version, Healthpfade und persistente Eventannahme | n8n-Phase: regulärer Modus, Crash-/Duplikat-/Readiness-Test |
| OP00.06 | Exakte Quellenfeeds, CDN-/Redirecthosts und Quoten | Import-/Enrichmentphase: versionierte Quellenkonfiguration, keine pauschalen Cloud-Wildcards |
| OP00.07 | Grants, FKs, RLS, Poolisolation, paralleler Adminschutz und Jobfencing | Datenbank-/API-Phase: reale PostgreSQL-Negativ- und Konkurrenztests |
| OP00.08 | Interne Token-Signatur/Rotation und mTLS-Peerweitergabe | Vor Service-Implementierung spezifizieren und falsche Audience/Caller/Replay testen |
| OP00.09 | Lastgrenzen, Argon2id-Kalibrierung, Retention, RPO/RTO | Sicherheits-/Betriebsphase: Messungen, Backup und Restore mit externem MFA-Schlüssel |
| OP00.10 | GitHub-Remote und gehostete CI | Nach separat autorisiertem Commit/Push tatsächlichen Workflow kontrollieren; lokal geprüft ist kein gehosteter Lauf |
| OP00.11 | Erledigt: Phase-2-Konzept nachgereicht und umgesetzt | Siehe Phase-2-Abnahme; Originalkonzepte unverändert |

Bereits ausführbar und in Phase 1 integriert: Inventarschema-/Formatvalidierung,
positive/negative Beispiele, OpenAPI mit lokalen Referenzen sowie zentrale Sicherheitsinvarianten.

Phase 2 schließt lokale TLS-/mTLS-/Health-/Netzprüfungen aus OP00.02 teilweise ab.
Produktive PKI/Widerruf und der geschützte Backend-Identitätskanal bleiben in Phase 8/11
nachzuweisen. OP00.03 betrifft weiterhin den noch nicht implementierten Envoy.
