# Sichere Uploaddiagnose

```bash
CVE_DOCKER_SUDO=1 make inventory-upload-check
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/inventory/verify-upload-contract.py
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/inventory/verify-mtls-configuration.py
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/inventory/inspect-technical-credentials.py
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/inventory/inspect-submission.py --submission-id <uuid>
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/inventory/check-inventory-permissions.py
CVE_DOCKER_SUDO=1 .venv/bin/python -m scripts.inventory.manage metrics
```

Inspektionen sind schreibgeschützt, DB-Transaktionen READ ONLY. Maximal 100 Metadatenzeilen,
keine Payloads, PEM-Körper, Verifikatoren oder Tokens. Prüfen Version, Hash, Quelle, Empfangs-
status, auslaufende Zertifikate, Widerruf und echte native Rechte. Aggregierte Zähler für
technische/Dashboardannahmen, Auth-/Rechte-/Schema-/Größen-/Parser-/Quotafehler und Duplikate,
Anzahl/Bytes/Alter ausstehender Annahmen. Latenzen in cve.inventory.<channel>-JSON-Logs.
Keine öffentliche Metrikschnittstelle, keine neue Monitoringdatenbank.

TLS-Fehler: Domain/SNI, CA, clientAuth, Datum und CRL prüfen; nie mit -k umgehen. 401:
Tokenstatus/Certificate-/Clientbindung prüfen, keine Secrets ausgeben. 403: Origin/CSRF/MFA/
Rollen prüfen. 404: eigene Serverbindung/ACL und Einliefereridentität prüfen. 409: Inventar-ID/
Inhaltskonflikt oder inaktives Ziel. 429: Rate-/Kapazitätsmetrik prüfen. 503: PKI und DB-Readiness.

Bei unklarem Commit identische eigene Anfrage mit gleichem Schlüssel wiederholen; der
persistente Datensatz entscheidet. Kein manueller Payloadoverwrite, keine automatische
Gruppen-/Serverreparatur. Native Fehler rollen Quota, Registry, Payload, Audit und Outbox
zusammen zurück. Diagnose/Retention benötigen ausdrückliche Betreiberentscheidung.
