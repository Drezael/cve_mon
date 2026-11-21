# Server über eine Inventardatei hinzufügen

Im Dashboard unter **Server → Serverinventar hochladen** eine JSON-Datei auswählen und
**Inventar einreichen** betätigen. Eine vorherige Serverregistrierung oder Zielserverauswahl
ist für das neue Format 1.2 nicht erforderlich. Hostname und Identität kommen aus der Datei.
Die Anwendung legt einen unbekannten Server an, ordnet ihn dem Benutzer zu und übernimmt
das Inventar. Weitere Uploads derselben Monitoring-ID aktualisieren denselben Server.
n8n gibt anschließend Inventarverarbeitung, Abgleich und Findings frei.

Die einzelne Rollenberechtigung **Server hinzufügen und aktualisieren**
(`server:inventory:manage`) genügt. Sie beinhaltet die lesenden Funktionen zum eigenen Bestand.
Neu angelegte Server erhalten automatisch die Leser-, Upload- und Finding-Leserechte für
ihren Ersteller. Lesende Rollen erhalten diese neue Berechtigung nicht automatisch.
Administratoren benötigen keine separate Upload-ACL. Fremde Server können normale Benutzer
nur mit einer ausdrücklich geteilten Uploadberechtigung aktualisieren. Die Kenntnis einer
Monitoring-ID oder eines SSH-Fingerprints verleiht keine Zugriffsrechte.

## Dateiformat

Inventar 1.2 enthält statt einer internen `server_id` den Bereich `host`:

```json
{
  "monitoring_id": "c974eb22-87fe-4d47-96e8-65c454c7f4bc",
  "hostname": "web01",
  "fqdn": "web01.example.test"
}
```

`monitoring_id` und `hostname` sind Pflichtfelder innerhalb von `host`. Zusätzlich sind ein
anwendungsspezifischer `machine_id_hash` (64 kleine Hexzeichen) und ein SHA256-Fingerprint
des öffentlichen SSH-Hostkeys möglich. Das vollständige Inventar benötigt weiterhin
Erfassungszeit, Inventar-ID sowie die technischen Bereiche aus 1.1.
Siehe [Schema](../../contracts/inventory/inventory-v1.2.schema.json),
[Beispiel](../../contracts/inventory/examples-v1.2/valid-discovery.json) und
[Uploadvertrag](../../contracts/api/inventory-discovery-v1.2.openapi.yaml).

Hostname und IP sind keine eindeutigen Identitäten. Ein neuer Host mit einer bereits
verwendeten Machine-ID oder einem bereits verwendeten SSH-Schlüssel wird nicht automatisch
mit einem Bestandsserver zusammengeführt. Widersprüchliche Kennungen führen zu einem
Konflikt. Ein SSH-Schlüsselwechsel bei gleicher Monitoring-ID ist möglich; eine gleichzeitig
abweichende vorhandene Machine-ID verlangt eine Prüfung. Administratoren können eine neue
Monitoring-ID über **Vorhandenem Server zuordnen (optional)** ausdrücklich mit einem bislang
nicht gebundenen Bestandsserver verknüpfen. Hier gelten dieselben Zugriffsprüfungen.

Die Formate 1.0 und 1.1 bleiben unverändert unterstützt. Deren interne `server_id` wird aus
der Datei gelesen; eine zusätzliche Auswahl ist nicht nötig. Diese alten Formate können
keinen unbekannten Server ohne Identitäts- und Hostdaten automatisch anlegen.

Serveranlage, Eigentümerrechte, Identitätsbindung und Annahme erfolgen atomar. Ein ungültiger
oder widersprüchlicher Upload hinterlässt keinen leeren Server. Originalbytes und JSON bleiben
unverändert; die interne Server-ID wird getrennt gespeichert. Wiederholte und parallele
Uploads erzeugen keine doppelten Server.

## Ansible

Die integrierte automatische Erfassung verwendet ausschließlich die Playbooks und
Collector-Helfer aus diesem Repository. Eine vorher registrierte technische
`server_uuid` ist nicht erforderlich. Die Verbindung wird im Dashboard eingerichtet;
Erfassung, Verarbeitung und Abgleich werden von n8n gesteuert.

Für eine lokale JSON-Datei kann derselbe Collector verwendet werden:

```sh
.venv/bin/python -m scripts.ansible.manage collect --config /private/target.json --output /private/inventory.json
```

Die private Zielkonfiguration und der SSH-Hostkey werden vorher eingerichtet und
bestätigt. Die Erfassung liefert Format 1.3, schreibt keine neue Host-ID auf dem
Ziel und installiert keine Werkzeuge. Eine vorhandene Monitoring-ID wird gelesen;
andernfalls wird sie stabil aus Hostinformationen abgeleitet. Klone benötigen
eindeutige System-Machine-IDs und SSH-Hostkeys. Bestehende ältere Inventarformate
bleiben für den Upload gültig.

[Playbooks, lokale Aufrufe und Voraussetzungen](../../integrations/ansible/README.md).

## Ein Zugang für mehrere Server

Die interne Client-/Zertifikatsverwaltung kann einen Collector-Zugang ausstellen.
Dieser technische Weg benötigt einen ausdrücklich im Repository eingerichteten
internen mTLS-Endpunkt; er wird im normalen Stack nicht öffentlich veröffentlicht.
Für externe Bedienung den Dashboard-Upload oder die integrierte SSH-Erfassung verwenden:


1. Technischen Client anlegen und dessen öffentliches mTLS-Zertifikat registrieren.
2. Beim Token-Ausstellen `owner_user_id` statt `server_id` angeben. Der Benutzer muss die
   Berechtigung `server:inventory:manage` besitzen. Der Token erhält `inventory:discover`.
3. Den Zugang in einer privaten Collector-Konfiguration hinterlegen. Dieser Zugang ist für alle
   vom zugeordneten Benutzer verwaltbaren Server nutzbar.

Client, Zertifikat und Token behalten Ablauf-, Widerrufs- und Rotationsschutz. Ein deaktivierter
Benutzer oder der Entzug seiner Verwaltungsberechtigung sperrt auch diesen Zugang. Teams
verwenden einen dafür vorgesehenen Benutzer und dessen Serverfreigaben. Es entstehen keine
unbeschränkten Plattform-Tokens. Bisherige servergebundene Tokens bleiben gültig.

[Automatische Prüfungen, Findings-Zähler und Server löschen](server-scans-and-deletion.md)

Docker-Images, Laufzeitpakete und eingebundene Anwendungen werden über
[Container-Softwareinventare](docker-container-inventory.md) erfasst und überwacht.
