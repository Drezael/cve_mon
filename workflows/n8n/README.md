# Zentrale Steuerung mit n8n

`cve-control-platform` ist der zentrale Anwendungsworkflow. Ein authentifizierter interner
Webhook weckt ihn bei neuen Aufträgen; ein Zeitplan alle zehn Sekunden holt verpasste
Ereignisse nach. Der sichtbare Graph verarbeitet zunächst die zentrale Datenbank-Queue mit
`cve-control-queue` und ruft danach acht fachliche Unterworkflows auf:
Import → Inventare → optionale Aufbereitung → Suchindex → Inventarabgleich → Findings
→ Benachrichtigungen → Systemprüfung.

Die Unterworkflows geben jeweils höchstens 64 wartende Aufträge pro HTTP-Aufruf frei und
holen weitere Pakete ab. Bereits freigegebene Aufgaben laufen parallel in den bestehenden
Python-Workern. Der Graph wartet auf Freigaben, nicht auf einen vollständigen CVE-Import.
Abhängige Schritte werden erst nach erfolgreicher Verarbeitung angefordert und beim
nächsten Durchlauf freigegeben. Auch technische Teilaufträge und Wiederholungen benötigen jeweils eine eigene
Freigabe aus der Queue. Der Übergang vom V5-Suchindex zum Abgleich erfordert eine neue
n8n-Freigabe. PostgreSQL speichert Aufträge, Leases, Wiederholungen und Ausführungsbelege;
der steuernde Graph liegt in n8n.

Der Import-Unterworkflow prüft den im Dashboard verwalteten Zeitplan (Standard 30 Minuten).
Er verwendet ausschließlich CVEProject/cvelistV5 über Git und inkrementelle Updates nach
abgeschlossenem Erstimport. Manuelle Aktualisierungen durchlaufen dieselbe Freigabe.
Ein CVE-Reset pausiert automatische Updates, bis diese bewusst wieder eingeschaltet werden.
Bei n8n-Ausfall bleiben neue Schritte dauerhaft wartend; laufende freigegebene Pakete dürfen
abschließen. Pause blockiert weitere Job-Claims, Abbrechen verwirft ausstehende Arbeit,
erhält jedoch gespeicherte CVEs und Inventare.

Aufträge, Ergebnisse und Ereignisse liegen dauerhaft in `automation.n8n_queue`.
Ein Klick auf „Datenbank aktualisieren“ legt nur einen Befehl ab; erst n8n erstellt
den Import. Warteschlangenposition und Zustand sind im Dashboard sichtbar.
Details: [Job-Queue und Fehlerbehandlung](../../docs/operations/n8n-job-queue.md).

## Betrieb

Bei **jedem Start des n8n-Containers** importiert und veröffentlicht der Bootstrap
alle JSON-Definitionen aus diesem Verzeichnis, einschließlich Benachrichtigungen
und Watchdog. Erst anschließend startet der unveränderte Hersteller-Entrypoint
den Server und aktiviert Zeitpläne/Webhooks. Die Definitionen liegen read-only
im Container; feste IDs aktualisieren bestehende Einträge statt Duplikate anzulegen.
Dies gilt auch bei einem direkten Docker-Neustart. `./cve_mon start` benötigt kein
Initialisierungsargument. Abweichende Definitionen werden beim nächsten kontrollierten
Start erkannt und durch einen Containerneustart übernommen.

Die zugehörigen verwalteten Credentials werden aus der privaten Dienstkonfiguration
synchronisiert; Verschlüsselungsschlüssel bleiben erhalten. Andere Workflow- und
Credential-IDs werden nicht entfernt. Ungültige Eingaben oder ein fehlgeschlagener
Import verhindern den Serverstart. Anwendungseinstellungen zu Importzeitplan,
Pause oder automatischen Updates werden beim Abgleich nicht überschrieben.

Für einen gezielten erneuten Containerstart beziehungsweise die Steuerungsdiagnose:

```sh
python -m scripts.workflows.manage install
python -m scripts.workflows.manage status
```

Bei einer leeren Erstinstallation aktiviert der Controller die Anwendungssteuerung
automatisch. Eine spätere explizite Aktivierung ist nach abgearbeiteten bisherigen
Aufträgen über `python -m scripts.workflows.manage enable` möglich.

`enable --manual-updates-only` aktiviert die zentrale Steuerung ohne automatische Imports.
Neustarts erhalten die gespeicherte Zeitplaneinstellung. Dashboard-Administratoren können
Zeitplan sowie Pause/Fortsetzen/Abbrechen verwalten. Ausführungs-IDs je Schritt verweisen auf
n8n; die Kontrollansicht verarbeitet keine CVE-Inhalte oder Inventarpayloads.

Die unveränderte n8n-Distribution nutzt Regular Mode. Ausschließlich die benötigten acht
Knotentypen sind per `NODES_INCLUDE` freigeschaltet. Definitionen enthalten Credential-IDs,
keine Geheimnisse. Acht getrennte Header-Credentials begrenzen die internen TLS-Aufrufe
auf den jeweiligen Schritt. Die Kontroll-API nutzt eine eigene Datenbankrolle ohne direkte
Schreibrechte auf CVEs oder Inventare. Der öffentliche Gateway veröffentlicht diese API nicht.
Der persistente n8n Encryption Key darf beim Neustart nicht wechseln.

Die sechs bestehenden Finding-Notification-Workflows bleiben aktiv. Sie steuern Versand,
Digest, Eskalation, Ausnahmen, Zustandsprüfung und Wiederaufnahme über authentifizierte APIs.
Python bestimmt Empfänger und MIME; das originale Postfix-Image übernimmt den Transport.
`cve-control-watchdog` prüft unabhängig vom fachlichen Graphen alle 30 Sekunden die
persistierten Dienstbeobachtungen und autorisiert bei drei Fehlprüfungen einen
Prozessneustart. Der PostgreSQL-Knoten benötigt keinen funktionierenden HTTP-Steuerdienst.
Auch der Watchdog wird bei jedem Containerstart auf den Repository-Stand gebracht und veröffentlicht.
[Grenzen, Audit und Neustartlimits](../../docs/operations/microservice-restarts.md).

Docker-Start, Netzwerkfreigaben, Migrationen und die Erhebung der Healthchecks liegen
weiterhin außerhalb von n8n. Die Entscheidung zur automatischen Prozesswiederherstellung
trifft der n8n-Watchdog. Die Plattform kann sich damit unabhängig von einem laufenden
n8n starten und bei einem n8n-Ausfall diagnostizieren lassen.
