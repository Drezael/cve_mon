# Inventare einliefern und prüfen

Seit Schema 1.2 und Migration `00041_server_discovery` gilt der vereinfachte
[Onboarding-Ablauf](server-onboarding.md): Upload ohne Vorabregistrierung,
automatische Serveranlage und wiederverwendbare Collector-Zugänge. Die folgenden
Abschnitte beschreiben den erhaltenen ursprünglichen Uploadvertrag.


Verbindliche Payloaddatei: contracts/inventory/inventory-v1.schema.json. Schema 1.0,
server_id/inventory_id als kanonische UUIDs, captured_at mit Zeitzone und maximal fünf Minuten
Zukunft. Collector/OS/Sektionen gemäß vorhandenen Beispielen. Keine Verwaltungsfelder.

Technisch: POST /api/v1/inventories auf INVENTORY_DOMAIN mit aktuellem Clientzertifikat/-key,
CA-Prüfung, Authorization: Bearer und application/json. Secret nicht in Logs, Shellhistory,
URLs oder Prozessargumente schreiben; HTTP-Client über geschützte Konfiguration versorgen.
Dashboard: eigener HTTPS-Origin, Cookie/CSRF, multipart server_id und genau eine JSON-Datei.
Optionaler Idempotency-Key [A-Za-z0-9._:-], 1–128 Zeichen; Standard ist inventory_id.

HTTP 202 bestätigt Commit und ausschließlich accepted. Location/status_url führt zur
jeweils geschützten Statusroute. Gleiche Wiederholung ist 202/duplicate=true. 409 erfordert
bewusste Konfliktklärung; neue Bytes unter identischer inventory_id sind kein Update.
404 gibt keine fremden Objektinformationen preis. 400/415/422 Eingabe korrigieren;
413 Nutzlast begrenzen; 429 begrenzt warten, ohne neue Idempotenzschlüssel zu erfinden;
503 mit demselben Schlüssel wiederholen und Status prüfen. Keine blinden Retries nach 409.

Grenzen: höchstens 10 MiB JSON, zusätzlich höchstens 1 MiB Multipartoverhead, kleinere
INVENTORY_MAX_BYTES konfigurierbar. Nginx respektiert zusätzlich vorhandene Bodylimits.
Maximale Tiefe 32, Arraylänge 100000, 750000 Knoten, 128 Schlüssel/Objekt, 64 KiB Einzelstring
zuzüglich engerer Schemagrenzen. Ein Parser gleichzeitig; 256 MiB Adressraum, 12 CPU-Sekunden,
15 Sekunden Walltime, harte Beendigung und Reaping. API-Containerbudget 512 MiB. Streaming-
Bodydeadline zehn Sekunden; Queue bounded, Überlast 429. Keine Dekompression.

Persistente Minutenlimits: global 120, IP 60, Client 60, Token 30, Server 30, Benutzer 10;
HMAC-Schlüssel statt gespeicherter vollständiger IPs. Native Kapazität: 100 Receipts/Server,
10000 insgesamt, 1 GiB Originalbytes zuzüglich JSONB-/Index-/WAL-Overhead. Eigentümer kann
Limits nur ausdrücklich kontrolliert anpassen; keine automatische Löschung/Reparatur.
Phase 14 muss Verarbeitung/Retention und zugehörige Kapazitätszähler gemeinsam entwickeln.
