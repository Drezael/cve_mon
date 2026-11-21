# Server-Lebenszyklus betreiben

Zunächst regulär als Administrator anmelden, CSRF und frische Reauth erhalten.
MFA ist optional; bei aktivierter MFA den zusätzlichen Anmeldeschritt abschließen.
POST dashboard/admin/servers mit request_id, display_name und optionalen Metadaten.
Keine UUID/Hostname-/IP-Registrierung verwenden. Für jeden geplanten Neuanlageversuch eine
neue Client-request_id; Retry desselben Vorgangs mit derselben ID und denselben Feldern.

GET liefert ETag. PATCH/Archive/Restore und Gruppenzuweisung benötigen den aktuellen
If-Match-Wert einschließlich Anführungszeichen. 428: neu lesen; 412: neu lesen und eigene
Entscheidung überprüfen; 409: fachlichen Konflikt auflösen. Keine blinde automatische Wiederholung.
POST archive/restore übermittelt außerdem einen begrenzten reason. Archivierung bewahrt
UUID, Snapshots, Historie, ACL und Mitgliedschaften; aktive Listen blenden den Server aus.
Restore verwendet dieselbe UUID und hängt seine aktiven Positionen neu an. Historische
Positionen werden im Audit referenziert.

Davon getrennt führt `DELETE /api/v1/dashboard/servers/{id}` eine endgültige Löschung
aus. Erforderlich sind die Berechtigung `server:inventory:manage`, Eigentum am Server
oder die Administratorrolle sowie dessen aktueller `If-Match`-Wert. Diese Löschung
entfernt auch Inventare, Findings, Ansible-Zugangsdaten und Läufe, zugehörige
Steuerungsaufträge sowie Referenzen in Warteschlangen und Auditdaten. Sie lässt sich
nicht durch Restore rückgängig machen. Verwaltete Sicherungen dieses Projekts werden
ebenfalls bereinigt, damit sie den gelöschten Server nicht wieder einspielen können.

Die Ermittlung der betroffenen Datensätze verwendet Referenz-, Fremdschlüssel-
und Primärschlüsselindizes. Auch die Zuordnung zu n8n-Ausführungen und Maildaten
verwendet typisierte Schlüssel, keine Vollvergleiche großer JSON-Datensätze.
Während der Vorbereitung werden weder globale Sicherheits-/Queue-Sperren noch
eine Serversperre gehalten. Erst beim Abschluss wird der Zielserver gesperrt und
seine bestätigte Version erneut geprüft.

Die nötige n8n-Koordinationssperre wird höchstens 100 ms lang angefordert. Ab Beginn
dieses Abschnitts begrenzt PostgreSQL die Transaktion auf 750 ms einschließlich
Commit. Ein Überschreiten beendet ausschließlich diese Datenbankverbindung und
rollt ihre Änderungen zurück; Koordinationssperren werden dabei freigegeben.
Die Löschroutine verwendet keinen globalen Login-/Berechtigungslock.

**Fehlgeschlagene Löschungen werden nicht automatisch wiederholt.** Der
Host-Controller markiert den Auftrag dauerhaft als `failed` und entfernt alte
Wiederholungszeiten. Ein Controller-Neustart stuft unterbrochene Aufträge als
abgebrochen ein und führt sie ebenfalls nicht erneut aus. Eine neue Löschung
benötigt eine neue ausdrückliche Bestätigung des Benutzers.

Abbrüche stehen mit Zeitpunkt, Auftrags-/Serverkennung, Fehlercode und verständlichem
Grund in `.runtime/automation-executor/<project>/erasure.log` sowie im Controllerlog
(`journalctl --user -u cve-automation-control-<project>`). `automatic_retry: false`
kennzeichnet das Verhalten. SQL-Texte, Inventarpayloads und Zugangsdaten werden nicht
protokolliert. Das private Auftragsjournal bewahrt die letzte erreichte Phase für
die Diagnose. Auch Fehler bei Sicherungs- oder Erfassungsdienst-Bereinigungen werden
abgebrochen und protokolliert. Eine Löschung startet keine Container neu.
