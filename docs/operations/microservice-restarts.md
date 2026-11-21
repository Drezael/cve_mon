# Microservices über n8n neu starten

In „Systemstatus“ können Administratoren einen Microservice auswählen und mit
Begründung einen Neustart anfordern. Die Berechtigung `deployment:service:restart`
ist ausschließlich der Systemrolle Admin zugeordnet und nicht delegierbar. MFA
bleibt entsprechend der Kontoeinstellung optional. Session, CSRF und ein UUID-
Idempotency-Key sind erforderlich.

Jede Dienstzeile besitzt höchstens einen Neustart-Button. Auch eine Pipeline
zeigt nur die Aktion für ihren Hauptdienst: Inventarverarbeitung → Inventory
Processor, CVE V5 → Importer, Sicherheitsbewertung → Matching Engine,
Benachrichtigungen → Notification Worker. Die zentrale n8n-Steuerung besitzt
keinen eigenen Prozessneustart-Button. Weitere beteiligte Microservices lassen
sich über ihre jeweilige Dienstzeile gezielt neu starten.

Der API-Aufruf erstellt `status.service_restarts` und einen `service.restart`-
Befehl in `automation.n8n_queue`, startet aber keinen Prozess. Der Queue-Workflow
übernimmt den Befehl in der normalen Reihenfolge, prüft die Berechtigung erneut
und speichert seine Freigabe samt n8n-Ausführungs-ID. Erst danach darf der vorhandene
Host-Control-Agent diesen konkreten Auftrag beanspruchen. Parallele Neustarts für
denselben Dienst werden verhindert. Bei gestopptem n8n bleibt der Auftrag wartend.

Der Host-Agent verwendet ausschließlich `docker exec` gegen einen fest zugeordneten
Anwendungscontainer. Der interne Prozessmanager beendet nur den ausgewählten
Microservice mit SIGTERM, wartet bis zu 30 Sekunden auf das Beenden und startet ihn
innerhalb desselben Containers neu. Überfällige Prozesse und ihre Prozessgruppe
werden beendet. Anschließend wird bis zu 30 Sekunden auf die Readiness gewartet.
Container-ID, Container-Startzeit, Netzwerkfreigaben und andere Microservices
bleiben unverändert. Es gibt keinen Docker-Restart-, Recreate- oder Start-Fallback.
Auch beim Ausfall eines Kindes bleibt der Prozessmanager mit den übrigen Diensten
im laufenden Container verfügbar und wartet auf einen gezielten Neustartauftrag.

Neustartbar sind API, Inventarverarbeitung, Importer, optionale Aufbereitung,
Matcher, Findings, Benachrichtigungen, Dispatcher und Ansible-Executor. Virtuelle
Queues und Infrastrukturcontainer sind keine Neustartziele dieser Funktion.
Die Anwendung erhält weder einen Docker-Socket noch frei wählbare Shellbefehle.

Die Ausführung besitzt eine gefencte Lease und einen lokalen Beleg je Auftrags-UUID.
Eine erneut zugestellte UUID liest diesen Beleg, statt den Prozess noch einmal neu
zu starten. Der Host-Agent speichert Abschluss oder Fehler sowie Prozess-IDs und
stellt das Ergebnis erneut in die n8n-Queue. Die Oberfläche zeigt Anfrage, Freigabe,
Ausführung und Ergebnis getrennt. Fehlgeschlagene Neustarts werden nicht endlos
automatisch wiederholt; nach Behebung der Ursache kann ein neuer Auftrag entstehen.

Für Bestandsinstallationen muss die Version mit dem internen Prozessmanager zuerst
regulär bereitgestellt sein. Die Neustartfunktion selbst ersetzt oder startet
keinen Container. Ein notwendiger erstmaliger Versionsrollout ist von dieser
Bedienfunktion getrennt und darf eine Vorgabe gegen Container-Neustarts nicht umgehen.

Die zusätzliche Hintergrundprüfung läuft im eigenständigen n8n-Workflow
`cve-control-watchdog` alle 30 Sekunden. Der vorhandene Host-Control-Agent prüft
parallel die festen lokalen `/health/live`-Endpunkte aller neun Microservices und
die Docker-Healthchecks der fünf Infrastrukturcontainer. Das geht auch bei einer
blockierten API oder Benachrichtigung: n8n liest die gespeicherten Beobachtungen
direkt über TLS aus PostgreSQL, ohne den üblichen HTTP-Steuerpfad zu benötigen.
n8n erlaubt vier parallele Produktionsläufe, damit auf HTTP-Timeouts wartende
Steuerabläufe den unabhängigen Watchdog nicht verdrängen. Es werden keine
Programme in Herstellerimages installiert oder verändert.

Drei aufeinanderfolgende Fehlprüfungen bestätigen einen nicht reagierenden Prozess.
Erst der geplante n8n-Lauf autorisiert dann einen dauerhaften Prozessneustartauftrag
in `automation.n8n_queue` und `status.service_restarts`. Vor Ausführung prüft der
Host-Agent erneut anhand aktueller Beobachtungen, ob die Wiederherstellung noch
nötig ist. Ein bereits erholter Dienst erhält keinen unnötigen Neustart.
Das Audit nennt als Auslöser `n8n-service-watchdog`.

`status.watchdog_probes` speichert letzten Prüfzeitpunkt, Fehlerfolge, Diagnose
und letzte Neustartentscheidung; `status.watchdog_runs` den letzten n8n-Lauf.
Bei mehr als 75 Sekunden alten Beobachtungen wird nicht automatisch neu gestartet.
Unterbrochene Prüfserien beginnen wieder bei eins. Ein Docker-/Containerfehler ist
kein Anlass, einen Container neu zu starten. Infrastrukturfehler werden erfasst;
die fünf unveränderten Herstellercontainer sind keine automatischen Neustartziele.
Bei ungesundem PostgreSQL, aktiven Wartungsfenstern oder einer bereits laufenden
Wiederherstellung wird kein weiterer Prozessneustart beauftragt. Die Prüfung
betrachtet Erreichbarkeit, nicht Rückstau, Datenalter oder bewusst pausierte Jobs.

Die in PostgreSQL gespeicherten Betriebswerte in `status.watchdog_settings` sind
standardmäßig aktiviert: Fehlergrenze 3, mindestens 300 Sekunden Abstand und
höchstens 3 Neustartentscheidungen pro Dienst und Stunde. Auch manuelle Neustarts
zählen zum Stundenbudget. Diese Werte und die Belege überleben Prozess- und
Containerneustarts. Der unabhängige Workflow kann in n8n deaktiviert werden;
reguläre Deployments überschreiben einen vorhandenen Workflow und seine Aktivierung
nicht. Für eine vollständige Wartung kann ein Administrator zusätzlich
`enabled=false` in `status.watchdog_settings` setzen.

Der Watchdog kann einen gestoppten n8n-, PostgreSQL-, Host-Control-Agent- oder
Docker-Dienst nicht selbst wiederherstellen. Das erfordert den externen Betrieb
bzw. dessen vorhandenen Service-Manager. Nach deren Rückkehr setzen gespeicherte
Neustartaufträge und die bestehende Job-Wiederaufnahme fort.
