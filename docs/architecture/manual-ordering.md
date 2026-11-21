# Persistente manuelle Reihenfolgen

Drei Kontexte: groups in server_groups.sort_order; servers global in servers.display_order;
group:<UUID> in server_group_memberships.display_order. dashboard.order_versions verwaltet
je eine positive monotone Revision. Die vorhandene Legacy-Ansicht für ungegruppte Server
bleibt kompatibel, ist nicht die globale Gesamtserverreihenfolge.

GET des jeweiligen admin/.../order liefert Revision/ETag und höchstens 100 Einträge plus total.
PUT mit If-Match übermittelt entweder ids als vollständige eindeutige aktive Liste (maximal
100 UUIDs) oder move_id/before_id als begrenzten relativen Befehl. before_id=NULL bedeutet
ans Ende. Große Bestände verwenden die relative Operation; die Ziel-UUIDs stammen aus
paginierten eigenen Listen. Der Server aktualisiert Positionen in einer SQL-Bulkoperation.

Globale administrative Reauth-/Inventarsperre serialisiert diese erste Implementierung;
verschiedene Kontexte haben dennoch unabhängige Revisionen und Positionen. Kein N+1 bei
der Neuordnung. Die Positionierung ist O(N) im Kontext; sehr große Bestände werden in Phase 23
weiter optimiert. Fehlende UUIDs oder unvollständige Gesamtlisten werden abgelehnt.

Unique-Constraints sind deferrable, positions >= 0 und im globalen Serverkontext NOT NULL.
Historische Positionen archivierter Objekte bleiben reserviert; aktive Neuordnung beginnt
oberhalb reservierter Positionen. Aktive Ansichten filtern Archiviertes. Wiederherstellung
hängt Server global und in jeder bestehenden Gruppe, Gruppen global ans Ende. Archivierung,
Wiederherstellung, Neuanlage und Mitgliedschaftsänderungen invalidieren betroffene Kontexte.
Globale Server-/Gruppenneuordnung erhöht zusätzlich die betroffenen Objektversionen.
Keine Kollisionen, keine verlorenen Änderungen; bei Überlauf kontrollierter Rollback 409.
Primärgruppenwechsel verändert keine Positionen. Technische Rollen haben keine Sortierwrites.

Ein außerhalb der API neu angelegter Kontext ohne gespeicherte Revisionszeile hat die
explizite Startrevision 1. Seine erste Mutation persistiert mindestens 2; ein zuvor
gelesenes ETag 1 kann daher nicht erneut schreiben. Reguläre Gruppenerstellung initialisiert
den Kontext ausdrücklich. Die Migration initialisiert vorhandene Gruppen.
