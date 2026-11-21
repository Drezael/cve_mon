# Inventarvertrag v1 — T00.03.01–04

Verbindlich: [inventory-v1.schema.json](inventory-v1.schema.json), JSON Schema Draft 2020-12.
`schema_version` ist exakt `1.0`. Unbekannte Versionen werden abgelehnt und nicht geraten.
Jede Objektebene ist geschlossen (`additionalProperties: false`), auch Paket-, Quellpaket-,
OS-, Dienst- und Containerobjekte. Keine Gruppen-/Sortierbefehle, keine frei erweiterbaren Metadaten.
UUIDs sind kanonisch klein geschrieben. Hostname ist keine dauerhafte Identität und ersetzt keine UUID.

| Feld | Pflicht / Bedeutung |
|---|---|
| schema_version | Ja; unveränderlicher Vertrag 1.0 |
| server_id | Ja; UUID eines vorab administrativ registrierten Servers |
| inventory_id | Ja; globale UUID dieses Erfassungsergebnisses, bleibt bei Wiederholungen gleich |
| captured_at | Ja; RFC3339 mit Z oder numerischem Zeitzonenoffset |
| collection_status | Ja; complete / partial / failed |
| collector | Ja; name=ansible, version, optional controller_id; reine Herkunftsinformation, keine Autorisierung |
| os | Ja; Status und bei nutzbaren Daten distribution/release/architecture/kernel |
| packages | Für complete erforderlich; Status und Paketliste, sonst optional |
| services | Optional; Status und Dienstliste |
| containers | Optional; Status und Docker-Metadaten |

Alle Informationen werden manuell über bestehendes Ansible erzeugt. Submit überträgt vorhandene
Dateien, installiert keine Agenten und löst keine automatische Inventarisierung aus.
Ein Server muss vorab über die Dashboard-Administration registriert sein; Uploads ändern
keine Stammdaten, Lebenszykluszustände, Gruppen, Primärgruppen oder manuellen Positionen.

## Vollständigkeit T00.03.03

Ein Bereich hat status complete, partial, failed oder not_collected. Fehlender optionaler
Bereich bedeutet not_collected; niemals leer. complete benötigt items (auch [] ist ein
positiver Nachweis eines leeren Bereichs), partial benötigt mindestens ein bekanntes Element.
failed/not_collected verbieten items/data. Ein leerer OS-Datensatz ist nicht zulässig.
OS complete verlangt Distribution, Release, Architektur und Kernel, partial mindestens ein Feld.
error_code ist ein begrenzter maschinenlesbarer Fehler, kein rohes stderr oder Secret.

Gesamt-complete bestätigt vollständiges OS und vollständige Paketabfrage. Optionale Bereiche
sind entweder complete oder nicht angefordert/not_collected. Gesamt-partial verlangt mindestens
einen nutzbaren Bereich, macht aber keine Vollständigkeitszusage. Gesamt-failed verbietet jeden
nutzbaren Bereich; es dokumentiert einen gescheiterten Erfassungsversuch.
Ein teilweises Ergebnis kann konservativ als partial gekennzeichnet werden, auch wenn einzelne
Kernbereiche vollständig sind. Kein Client darf es nachträglich zu complete aufwerten.

Paket: name, vollständige version, architecture und package_manager. source_package ist optional,
mit Name und gegebenenfalls vollständiger Version. Keine Kürzung von Epoch, Tilde, Release- oder
Distributionsrevision; kein allgemeiner lexikographischer Versionsvergleich.
Dienste haben Name/Zustand und optional enabled/version. Container haben Identität,
Image-Referenz, optional Digest, Zustand und eigenen Erfassungsstatus. Image-Referenzen lösen
keine automatischen Registry-Aufrufe aus; fehlende Metadaten bedeuten unbekannt.

Maximal 100000 Elemente je Bereich, Strings begrenzt, maximal 10 MiB JSON nach Dekodierung;
Dateigrößenlimit und Zeitpunktplausibilität sind Annahmeprüfungen zusätzlich zum Schema.
Doppelte JSON-Objektschlüssel, NaN/Infinity und ungültiges UTF-8 werden abgelehnt.

## Beispiele und Prüferwartung T00.03.04

| Datei | Erwartung / Aussage |
|---|---|
| examples/valid-ubuntu.json | Akzeptiert; Ubuntu, vollständige Distributionsrevisionen, erfolgreich leere Dienstliste |
| examples/valid-partial.json | Akzeptiert; Paketabfrage fehlgeschlagen, kein leerer Softwarebestand behauptet |
| examples/valid-with-containers.json | Akzeptiert; begrenzte Docker-Metadaten, synthetischer Digest |
| examples/invalid-group-assignment.json | Abgelehnt; verschachtelte group_ids sind administrative Steuerdaten |
| examples/invalid-server-id.json | Abgelehnt; Server-ID ist keine UUID |
| examples/invalid-timestamp.json | Abgelehnt; Zeitzonenbezug fehlt |

Alle Beispiele sind synthetisch, keine realen Serverinventare oder Zugangsdaten.
`make validate` prüft positive UND negative Erwartungen mit aktivierter UUID-/Zeitformatprüfung.
[Annahme, Ablehnung und Historisierung](rejection-cases.md).

## Ergänzung Phase 12: gemeinsamer Vertrag 1.1

[inventory-v1.1.schema.json](inventory-v1.1.schema.json) ergänzt versioniert Hardware,
OS-Familie/Kernelversion, RPM-Einzelfelder, Service-Manager und Docker-Image-/Containerdaten.
1.0 bleibt unverändert und gültig. Für 1.1 gelten dieselben UUID-, Status-, Größen- und
Datenhoheitsgrenzen. Alle Objekte bleiben geschlossen; keine freien Verwaltungsmetadaten.
Neue Beispiele liegen getrennt unter examples-v1.1/, die historische Sechser-Testmatrix
bleibt erhalten. Annahme ab API 0.11.1/Revision 00018 unterstützt beide Versionen.
[Entscheidung](../../docs/architecture/decisions/ADR-0030-inventory-collection-phase12.md).
