# Servicekatalog

Der bestehende Stack umfasst acht Container: drei eigene Anwendungscontainer und
fünf unveränderte Infrastruktur-Images. Der Status unterscheidet 19 logische Dienste
und Komponenten; deren Anzahl ist keine Containeranzahl.

Die zentrale Steuerung wird getrennt gemessen: n8n-Laufzeit, tatsächlicher Kontakt
des Workflows `cve-control-queue` und Fortschritt der PostgreSQL-n8n-Queue.
Workflow-Kontakte werden auch bei leerer Queue erfasst. Nach 60 Sekunden ohne
Kontakt ist die Steuerung eingeschränkt, nach 180 Sekunden nicht verfügbar; ohne
Messung bleibt ihr Zustand unbekannt. Deaktivierte Steuerung wird explizit angezeigt.
Queue-Alter berücksichtigt nur fällige, nicht pausierte Nachrichten. Abgelaufene
Leases und fehlgeschlagene Nachrichten werden gesondert gezählt.

Fünf Pipelines zeigen zentrale Steuerung, Inventarverarbeitung, V5-Git-Import und
Suchindex, Sicherheitsbewertung sowie Benachrichtigungen. Die optionale Aufbereitung
ist keine Voraussetzung des V5-Abgleichs. Die Abhängigkeiten der Worker enthalten
die zentrale Steuerung und deren Queue. IDs und gerichtete Abhängigkeiten stehen
in `cve_api.status.catalog`; der Graph wird auf Zyklen geprüft und persistierte
Entitäten werden bei Konfigurationsänderungen aktualisiert.

Die Übersicht und Neustartaufträge werden ausschließlich beim Öffnen und auf
expliziten Klick aktualisiert. Der Hintergrund-Collector misst weiterhin unabhängig davon.
Die übrigen technischen Messungen behalten ihren eigenen Messzeitpunkt und ihre
Frischegrenzen. Ein n8n-Ausfall kann deshalb ältere Fachmessungen veralten lassen;
die unabhängige Leseabfrage der Queue bleibt über die API verfügbar.

[Prozessneustarts über n8n](../operations/microservice-restarts.md)


n8ns technische Healthprüfung erfolgt über einen festen internen Health-Endpunkt
des Processing-Diensts. Der Status-Collector erhält dadurch nur den geprüften
Zustand; der isolierte n8n-Netzbereich wird für die API nicht geöffnet. Der
Notification-Worker wird unabhängig von seinen separat erfassten Abhängigkeiten
geprüft. Ungeprüfter Envoy-Verkehr ist keine pauschal fehlschlagende Pflichtprüfung;
Envoys lokaler Bereitschaftsadapter bleibt maßgeblich für seine Erreichbarkeit.
Die CVE-Frischegrenze wird aus dem tatsächlichen n8n-Updateintervall abgeleitet
(zwei Intervalle plus fünf Minuten). Ohne geplante Updates gilt eine explizite
manuelle Aktualisierungsrichtlinie. Historische Prüfdimensionen bleiben in der
Historie und werden nicht als aktuelle Messungen einer neuen Collector-Ausführung angezeigt.
