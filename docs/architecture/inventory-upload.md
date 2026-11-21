# Zwei getrennte Eingänge, ein Annahmeservice

Seit Schema 1.2 und Migration `00041_server_discovery` gilt der vereinfachte
[Onboarding-Ablauf](../operations/server-onboarding.md): Upload ohne Vorabregistrierung,
automatische Serveranlage und wiederverwendbare Collector-Zugänge. Die folgenden
Abschnitte beschreiben den erhaltenen ursprünglichen Uploadvertrag.


cve-api 0.11.0 implementiert POST /api/v1/inventories ausschließlich auf dem bestehenden
INVENTORY_DOMAIN mit mTLS und Bearer. Nginx prüft Kette, Laufzeit, Verwendungszweck und CRL.
Eine getrennte private Capability und das tatsächliche escaped Clientzertifikat gehen zum
internen API-Pool; der Server berechnet SHA-256 über DER. Registrierung und gültiges Token
müssen Client, Zertifikat und genau eine aktive registrierte Server-UUID verbinden.

POST /api/v1/dashboard/inventories/upload benutzt die bestehende Dashboard-Origin, vollständige
Session/MFA, CSRF, inventory:upload:dashboard plus explizites can_upload/view-ACL. Auch ein
Plattformadmin braucht diese Freigabe. Genau ein file-Feld und server_id; Idempotency-Key
optional im Header. Zertifikat/Token ersetzen kein Cookie, Cookie ersetzt keine technische
Identität. Keine freie Herkunfts-, Rollen- oder Serverbehauptung aus JSON/Clientheadern.

Beide Router verwenden denselben ressourcenbegrenzten Parser, das unveränderte Inventarschema
1.0 und denselben Repository-Speichervorgang. Vorprüfung erfolgt vor Bodyverarbeitung;
Identität, Widerruf, Zielzustand und ACL werden vor Commit erneut geprüft. PostgreSQL hält
shared Security-Lock 909001; Konto-/ACL-/Credentialwiderruf und Serverarchivierung verwenden
exclusive. Lange Parsingarbeit liegt außerhalb der DB-Transaktion. Native Serverprüfung und
Quotas ergänzen die Serviceprüfung. Keine Gruppen-/Primärgruppen-/Sortier-/ACL-Änderungen.

Erfolg erst nach Commit: HTTP 202 mit submission_id/status=accepted/status_url. Duplikate
im eigenen Idempotenzkontext erhalten ebenfalls 202 und dieselbe ID, duplicate=true. Keine
Snapshot-/Job-ID und keine behauptete Fachverarbeitung. Phase 14 folgt ausdrücklich später.
[Zustände](inventory-submission-lifecycle.md), [Limits](../operations/inventory-upload.md).
