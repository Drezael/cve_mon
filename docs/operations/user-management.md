# Benutzer verwalten

Dashboard-HTTPS und Phase-8-Login/MFA verwenden; GET auth/csrf erneuert die Session-Challenge.
Mutationen benötigen Origin und X-CSRF-Token, Änderungen bestehender Objekte zusätzlich
Bodyversion/Grund sowie je Katalog frische einmalige
Reauthentifizierung. Benutzeranlage liefert pending_activation ohne Standardpasswort oder
Rollen. Anzeigename/Kontaktadresse sind die einzigen PATCH-Felder; username/UUID/Status/
Rollen/MFA/Credentials über diesen Weg nicht änderbar. Listen begrenzt und nach UUID sortiert.
User Admin sieht/verändert keine privilegierten Zielkonten. Archivierte Konten bleiben historisch
und können nicht per gewöhnlichem enable wieder aktiviert werden.

Manuelle Aktivierung: Hostoperator erstellt mit
`scripts/security/issue-activation.py --user-id <uuid> --output-file <neue-private-datei>`
einen höchstens eine Stunde gültigen Token (Datei 0600, O_EXCL, kein Symlink/Consolewert).
Nach unabhängig geprüfter Übergabe kann der Benutzer mit anonymem CSRF-Kontext
POST /api/v1/auth/activation/redeem (activation_token, new_password) einmal ein Passwort
setzen. Anschließend regulär anmelden und nötige MFA einrichten. Kein E-Mail-Versand behauptet.
Produktionstransport folgt Phase 19; Token niemals in URL, Logs oder Prozessargumente kopieren.

Versionkonflikt 409: aktuelle Daten neu lesen, Entscheidung/Version erneut prüfen. Fehlende
Reauth 403: neue Phase-8-Bestätigung. Wiederholung mit alter Version erzeugt keine zweite
Änderung. Status-/Rollen-/ACL-Entzug widerruft betroffene Sessions unmittelbar; erneute
Anmeldung erforderlich. Gründe sind begrenzte Bearbeitungsangaben; sensible Details gehören
nicht in Profile, Logs oder Eventpayloads. MFA-Anfragegrund wird nur im geschützten Request gespeichert.

## Arbeitsbereich, persönliche Einstellungen und Instanzverwaltung

**Administration** ist ausschließlich für die Rollen `admin` und `user_admin`
sichtbar und erreichbar. Die einzelnen Unterseiten verlangen zusätzlich ihre
jeweilige Berechtigung. Der Einstieg öffnet den ersten freigegebenen Bereich,
für die beiden Standardrollen die Benutzerverwaltung. `user_admin` erhält dadurch
keinen Zugriff auf zentrales SMTP, Versandregeln oder Vorlagen. Normale Konten
mit Server- oder Upload-Rechten erhalten keinen Zugang zur Administration.
Die APIs prüfen die jeweiligen Rechte weiterhin unabhängig von der Navigation.

Die Instanzverwaltung enthält Benutzer, Rollen, zentrales SMTP, Versandregeln,
Vorlagen und Audit. Eigene Benachrichtigungspräferenzen, Mail-Einstellungen und
Kontosicherheit liegen unter **Meine Einstellungen** (`/settings`), mit den
Benachrichtigungspräferenzen als Einstieg. Persönliche Mail-Konfigurationen bleiben
an das angemeldete Konto gebunden; alternativ kann das zentrale SMTP genutzt werden.

Serververwaltung (`/servers/manage`), Inventarupload (`/servers/upload`),
Gruppenverwaltung (`/groups/manage`), Reihenfolge (`/servers/order`), Server-ACL
(`/servers/access/:id`) und Finding-Bearbeitung (`/findings/:id/edit`) gehören
zum Arbeitsbereich. Links befinden sich bei den betreffenden Bestandsseiten.
Eine neue URL erweitert keine Rechte: Listen und Detailabfragen bleiben nach den
bestehenden Serverfreigaben gefiltert, Änderungen benötigen ihre eigenen
Berechtigungen. Es werden keine Rollen oder Freigaben automatisch hinzugefügt.

### Server anlegen

Der Button **Server anlegen** öffnet unter `/servers/new` direkt die gemeinsame
Eingabemaske **Server anlegen**, ohne vorherigen Auswahldialog. Dort stehen die
Stammdatenfelder und die optionale Auswahl einer Inventardatei bereit. Manuell
bereits eingetragene Beschreibungen und Einstellungen bleiben beim Laden erhalten.
Der Hostname füllt eine noch nicht selbst vergebene Serverbezeichnung voraus.
Die bisherigen Berechtigungen gelten je Speicherweg: `server:create` für eine
manuelle Anlage ohne Datei, `server:inventory:manage` für die Anlage aus einem
Inventar. Leserechte allein reichen nicht aus.

Die Inventardatei wird nach Auswahl vollständig im Browser eingelesen. Vor einer
Übertragung erscheinen Hostdaten, Paket- und Containerzahlen sowie das gesamte
JSON in einer aufklappbaren Vorschau. Dieser Entwurf wird weder im Backend noch
im Browserspeicher persistiert. Erst **Server speichern** überträgt genau den
geprüften Dateistand an die bestehende, serverseitig validierende Inventarannahme.
Dort erfolgen Serverzuordnung und die von n8n gesteuerte Verarbeitung. Bekannte
Serveridentitäten aktualisieren ihren Inventarstand gemäß den bestehenden Regeln.

**Inventar verwerfen** entfernt den Entwurf. Ein Dateiwechsel verwirft die vorherige
Vorschau sofort; ein verspätetes Leseergebnis kann die neue Auswahl nicht ersetzen.
Beim Verlassen mit ungespeicherter Datei erscheint eine Rückfrage. Bei unklarem
Übertragungsergebnis bleibt der vorhandene Abgleich über Inventar-ID und die
Idempotenz-ID erhalten; es gibt keine automatische erneute Speicherung.

Bei der Inventar-Anlage verwendet die Maske dieselben Stammdatenfelder wie die
manuelle Anlage. Die Serverbezeichnung wird aus dem Inventar-Hostnamen übernommen;
Beschreibung und Umgebung können ergänzt, Kritikalität und Erreichbarkeit gewählt
werden. Diese Felder werden getrennt vom technischen JSON übertragen und in derselben
Datenbanktransaktion wie die Inventarannahme gespeichert. Nur der Eigentümer oder ein
Instanzadministrator darf damit Server-Stammdaten ändern; eine reine Upload-Freigabe
auf einen fremden Server reicht nicht. Wiederholungen derselben Annahme prüfen die
ursprünglichen Stammdaten, überschreiben aber keine späteren Benutzeränderungen.
Automatisierte Folgeinventare ohne Stammdaten lassen diese Einstellungen bestehen.

Alle Inventarwerte sind zusätzlich als gegliederte Felder einsehbar. Monitoring-ID,
Hostname, FQDN, Maschinen-/SSH-Fingerprints, Software, Versionen und technische
Erhebungsmetadaten sind schreibgeschützt. Hardwareangaben und beschreibende Daten
zu Diensten sind bearbeitbar; dabei wird nur der lokale Entwurf verändert. Der
vollständige JSON-Stand in der Vorschau entspricht weiterhin dem zu speichernden
Inventar. Die Serverkennung und die Softwaredaten bleiben bei diesen Änderungen
unverändert. Die serverseitige Schemaprüfung gilt auch für bearbeitete Entwürfe.

Nach bestätigter manueller Serveranlage oder Inventarannahme leitet die Oberfläche
unmittelbar zur Serverübersicht (`/servers`) weiter. Dies gilt ebenfalls, wenn eine
zunächst unklare Inventarannahme nachträglich bestätigt wird. Fehler führen nicht
zur Weiterleitung; die Eingaben bleiben zur Korrektur erhalten.
