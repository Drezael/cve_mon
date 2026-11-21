# Zentrale n8n-Job-Queue

`automation.n8n_queue` ist die persistente Inbox der Steuerung. Alle fachlichen
Job-Vorschläge, terminalen Job-Ergebnisse, Outbox-Ereignisse und Zustellergebnisse
werden dort transaktional abgelegt. Manuelle und zeitgesteuerte CVE-Updates erzeugen
einen `command` vom Typ `cve.refresh`. Der HTTP-Aufruf erstellt noch keinen Import.
Erst n8n prüft den Befehl und erstellt beziehungsweise setzt den Import fort.

## Ablauf und Reihenfolge

`cve-control-platform` startet `cve-control-queue` vor den fachlichen Stufen.
Dieser Workflow beansprucht Nachrichten über die interne TLS-API und entscheidet
sichtbar zwischen `command`, `task`, `result` und `event`. Die Datenbank führt die
quittierte Entscheidung atomar aus. Freigegebene Aufgaben werden anschließend
parallel durch die bestehenden Python-Worker verarbeitet. Auch technische
Teilaufträge und Wiederholungen kehren zur Queue zurück.

Die Freigabe folgt der aufsteigenden Sequenznummer unter den bereits fälligen,
nicht pausierten Nachrichten. Ein noch gültig beanspruchter Kopf wird nicht
überholt. Eine Wiederholung mit späterem `available_at` blockiert andere bereits
fällige Arbeit nicht. Ein Durchlauf bearbeitet höchstens 64 Nachrichten; weitere
Durchläufe werden durch den zentralen Zeitplan gestartet. Fachliche Ausführung
und Abschluss müssen wegen der parallelen Worker nicht in FIFO-Reihenfolge liegen.

Der separate n8n-Watchdog besitzt einen unabhängigen Wiederherstellungspfad:
Sein periodischer Datenbankaufruf autorisiert bestätigte Prozessausfälle direkt
und protokolliert die Entscheidung transaktional als abgeschlossenen
`service.restart`-Befehl mit n8n-Ausführungs-ID in derselben Queue. Dadurch kann ein
blockierter HTTP-Consumer seine eigene Wiederherstellung nicht verhindern.
Der Host-Agent führt nur diese Freigabe aus; sein Ergebnis gelangt wieder als
`result` in die reguläre FIFO-Verarbeitung. Fachliche Befehle durchlaufen weiterhin
die reguläre Queue. [Details](microservice-restarts.md).

## Ausfall, Wiederholung und Berechtigungen

Eine Beanspruchung gilt 30 Sekunden. Lease-Token und n8n-Ausführungs-ID verhindern,
dass ein veralteter Consumer die Nachricht abschließt. Nach Ablauf kann n8n erneut
beanspruchen; nach fünf erfolglosen Beanspruchungen wird die Nachricht als
`failed` abgelegt. Wiederholtes Quittieren derselben bereits abgeschlossenen
Entscheidung liefert den gespeicherten Beleg, ohne den Auftrag erneut auszulösen.
Idempotency-Keys deduplizieren Dashboard-Befehle; parallele Update-Anfragen können
auf denselben aktiven Import verweisen.

Bei gestopptem n8n bleiben neue Aufträge in der Datenbank wartend. Bereits
freigegebene Arbeit darf abschließen. Der Wiederanlauf holt wartende Nachrichten
nach. Nur die interne Rolle `workflow_control` darf beanspruchen und entscheiden;
Anwendungsrollen haben keine direkten Schreibrechte auf die Queue. API und n8n
verwenden ihre vorhandenen getrennten Credentials.

Nachrichten enthalten Typen, Status und Referenzen auf Fachdatensätze. SSH-Zugänge,
E-Mail-Inhalte und vollständige Inventare werden nicht in die Queue kopiert.
Serverlöschung entfernt zugehörige Nachrichten und Ausführungsreferenzen zusammen
mit den Fachdatensätzen; gemeinsam verwendete n8n-Ausführungen anderer Server
werden dabei erhalten und die gelöschten Referenzen daraus entfernt.

## Anzeige und Diagnose

Die CVE-Anzeige zeigt einen wartenden Aktualisierungsauftrag samt Position bereits
vor dem Start des Imports. Die administrative Workflow-Steuerung zeigt offene,
beanspruchte und fehlgeschlagene Nachrichten sowie deren Sequenz und Ausführungs-ID.

Bei Stillstand zuerst n8n-Gesundheit, aktive Workflows und die älteste fällige
Nachricht prüfen. `failed`-Nachrichten bleiben als Diagnose erhalten und werden
nicht automatisch endlos wiederholt. Nach Behebung der Ursache kann eine neue
manuelle Aktualisierung mit neuem Idempotency-Key angefordert werden. Bei anderen
Job-Typen erfolgt die Wiederholung über die vorhandene Job-Steuerung. Direkte
Statusänderungen an Queue-Zeilen umgehen die Belege und sind kein regulärer Betrieb.

Die Queue benötigt weder einen zusätzlichen Container noch Redis. Start,
Migrationen, Netzwerkfreigaben und Liveness bleiben beim Plattformbetrieb, damit
die Dienste auch bei einem n8n-Ausfall gestartet und diagnostiziert werden können.
