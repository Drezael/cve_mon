# Server prüfen und aus dem Bestand löschen

Nach einem erfolgreichen Inventarupload übernimmt n8n die Verarbeitung und gibt den
Inventarabgleich frei. Der Erstabgleich berücksichtigt den gesamten aktuellen CVE-Bestand
über dessen Suchindex. Der Index grenzt die aufwendig zu prüfenden Kandidaten anhand der
inventarisierten Software ein; bekannte frühere Treffer werden ebenfalls erneut geprüft.
Eine Serveranlage ohne Inventar kann erst nach dem ersten Inventarupload geprüft werden.

CVE-Aktualisierungen verwenden weiterhin Git-Pull und Git-Diff. Nur neue, inhaltlich geänderte
oder entfernte CVEs erzeugen neue Indexpakete und Abgleichaufträge. Diese laufen unabhängig
vom angemeldeten Benutzer gegen passende aktuelle Inventare aller aktiven Server. Bereits
vorhandene Treffer werden auch dann berücksichtigt, wenn die Produktzuordnung im neuen
CVE-Dokument fehlt. Ein Update ohne Inhaltsänderung erzeugt keine weiteren CVE-Abgleiche.
Später hochgeladene Server werden gegen den gesamten dann aktuellen Bestand geprüft.

Unter **Server** beziehungsweise in den Serverdetails kann der Ersteller oder ein
Administrator einen Server über **Löschen** mit Bestätigung endgültig entfernen.
Inventare, Findings, Ansible-Konfiguration und Läufe, Aufträge und zugehörige Referenzen
werden gelöscht. Auch verwaltete Projektsicherungen werden bereinigt. Andere Server
und deren Findings bleiben erhalten. Eine Wiederherstellung des gelöschten Servers
über die Archivfunktion ist nicht möglich. Technische Abläufe und Wiederholungen sind
in [Server-Lebenszyklus](server-lifecycle.md) beschrieben.

Eine getrennte administrative Archivierung bewahrt die Historie. Archivierte Server
werden bei CVE-Updates und Backfills nicht mehr berücksichtigt. Bereits freigegebene
Abgleichaufträge prüfen vor ihrer Ausführung den aktuellen Serverstatus; die
Publikationssperre verhindert, dass parallele Entfernungen neue aktuelle Ergebnisse
veröffentlichen. Eine Wiederherstellung eines archivierten Servers durch einen
Administrator fordert über n8n einen erneuten vollständigen Inventarabgleich an.

Der Link **Findings** zeigt einen Zähler für offene beziehungsweise in Bearbeitung befindliche
Findings aktiver Server. Es zählen ausschließlich Findings im Lesebereich des angemeldeten
Benutzers. Bei null bleibt der Zähler vollständig ausgeblendet. Die Anzeige aktualisiert
sich alle zehn Sekunden und wird beim Benutzerwechsel verworfen.

Native Tests prüfen Erstabgleich, mehrere Benutzer, geänderte und neue CVEs, unveränderte
CVEs ohne zusätzlichen Abgleich, Updates ohne Diff, Löschungen und spätere Serverzugänge
mit einer echten n8n-Instanz und isolierten lokalen Git-Repositories.

Die geöffnete Findings-Liste fragt alle zehn Sekunden den aktuellen Stand ab, auch
wenn sie zunächst leer ist. Ein erneuter normaler Klick auf **Findings** in der
Hauptnavigation lädt die aktuelle Liste und den Zähler sofort neu, ohne Filter,
Sortierung oder die aktuelle Seitenauswahl zurückzusetzen. Während einer
Hintergrundabfrage bleiben die bisherigen Einträge sichtbar. Verbindungsfehler
beenden die Aktualisierung nicht; bei vorhandenen Daten erscheint ein Hinweis
und der nächste Versuch folgt automatisch. Beim Verlassen der Liste werden ihre
Abfragen abgebrochen und ihre Timer entfernt. Das automatische Nachladen gilt
für diese Ansicht; andere Seiten wie der Systemstatus bleiben davon unberührt.

Sobald die Zählerabfrage eine geänderte Anzahl aktiver Findings erkennt, fordert sie
zusätzlich sofort die Aktualisierung der geöffneten Liste an. So wird insbesondere
auch der Übergang von null auf das erste Finding ohne Benutzeraktion angezeigt.
Die regelmäßige Listenprüfung berücksichtigt außerdem Änderungen, bei denen die
Gesamtzahl gleich bleibt. Die Erkennung erfolgt im normalen Zehn-Sekunden-Takt;
Filter und Benutzerfreigaben gelten weiterhin.
