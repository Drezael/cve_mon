# Dashboard-Architektur

React 19, TypeScript 5.9 und Vite erzeugen statische HTML-, CSS- und JavaScript-Dateien. Der vorhandene Nginx liefert diese auf dem Dashboard-Host aus. FastAPI bleibt die einzige Fach-API, PostgreSQL die einzige Fachdatenbank. Es gibt keinen Node-Produktivdienst, keinen zusätzlichen Hostport und keinen direkten Browserzugriff auf PostgreSQL, Worker, SMTP oder n8n.

Migration 00028 ergänzt ausschließlich die minimierte Sicht dashboard.server_security und Leseprivilegien. Bestehende Quelldaten bleiben unverändert. scripts/dashboard/manage.py kapselt verifizierte Node-Installation, npm ci, Build und Aktivierung. contracts/api/dashboard-read.openapi.json wird aus denselben FastAPI-Routern exportiert; daraus entsteht src/generated/api.ts. Zod validiert Antworten zur Laufzeit.


## Lokalisierung (Deutsch und Englisch)

`services/dashboard/src/i18n/` enthält die zentralen, gemeinsam geladenen
Sprachkataloge `de.json` und `en.json`. Die deutschen Quelltexte dienen als stabile
Nachrichtenschlüssel. `t("Server {0} löschen", [name])` ersetzt ausschließlich
Textparameter, ohne HTML auszuwerten. Neue Übersetzungen werden in beiden Katalogen
ergänzt; Tests prüfen Vollständigkeit, gleiche Parameter und die vorhandenen
Übersetzungsaufrufe. Eigennamen, Inventarinhalte, CVE-Quelldaten, API-Schlüssel,
Statuscodes und Formularwerte werden nicht als Nachrichten übersetzt.

`useLocale()` bindet Komponenten über React `useSyncExternalStore` an die aktuelle
Sprache. Die Auswahl steht ausschließlich unter „Meine Einstellungen → Sprache“.
Eine bestätigte Änderung aktualisiert Texte, zugängliche Beschriftungen,
Dokumenttitel, `html[lang]` sowie Zahlen-, Prozent- und Datumsformate unmittelbar,
ohne Navigation oder Neuladen. Andere offene Formulare behalten ihre Eingaben.

Migration `00069_account_locales` speichert die persönliche Präferenz in
`security.user_preferences` (nullable `locale`, Version und Änderungszeit). `NULL`
bedeutet, dass der aktuelle Instanzstandard gilt. `security.instance_preferences`
enthält genau einen Standard. `DEFAULT_LANGUAGE` in Compose wird beim ersten
API-Start atomar initialisiert; ohne Vorgabe gilt Englisch. Existiert bereits ein
Wert, ignoriert die Startfunktion sämtliche Umgebungswerte. Administratoren ändern
ihn über „Administration → Instanzeinstellungen“; nur die Rolle `admin` erhält die
nicht delegierbare Berechtigung `instance:settings:manage`.

Die API liefert den öffentlichen Standard unter `/api/v1/dashboard/localization`;
sie enthält keine Kontodaten. `/api/v1/dashboard/me/locale` adressiert ausschließlich
den durch die geprüfte Sitzung ermittelten Benutzer, auch ohne fachliche Rolle.
Der Browser sendet keine Benutzer-ID. Schreibzugriffe benötigen CSRF und `If-Match`;
veraltete Versionen werden mit 412 zurückgewiesen. Account- und Standardänderungen
werden mit menschlichem Akteur auditiert, die Erstinitialisierung mit dem technischen
Akteur `localization-service`. Tabellen sind nicht direkt für die Lesedatenbankrolle
freigegeben; begrenzte Datenbankfunktionen prüfen Sitzung und Rechte erneut.

Bei der Anmeldung wird die effektive Kontosprache geladen; vor der Anmeldung und
nach Abmeldung gilt der gespeicherte Instanzstandard. Der normale Sitzungsabgleich
liest die aktuelle Sprache erneut. Ein BroadcastChannel fordert andere Tabs zur
Neuabfrage ihres eigenen Kontos auf; er überträgt keine Kontopräferenz. Ältere
Abfragen dürfen eine gerade gespeicherte Auswahl nicht überschreiben. Bei einem
vorübergehenden Ausfall der Sprachabfrage bleibt die Anmeldung verfügbar. Die alte
browserlokale Auswahl wird verworfen und nicht automatisch in ein Konto importiert.
Es werden keine Sprachpräferenzen mehr in LocalStorage gespeichert.

Sprache ändert keine fachlichen Zeitzonen, Scanzeitpläne oder SMTP-Einstellungen.
Die Lokalisierung betrifft die Weboberfläche; CVE-Originaltexte und Mailvorlagen
werden inhaltlich nicht automatisch übersetzt.

Statische Formulardefinitionen und Statusbezeichnungen verwenden `localized()`;
dieses liest übersetzbare Anzeigetexte erst beim Zugriff und behält Schlüssel,
Objektidentitäten und technische Optionswerte bei. `translateMessage()` wird nur
für anwendungseigene Meldungen und Formulartitel verwendet, die bereits vor einem
Sprachwechsel im Zustand lagen. Es darf nicht auf Benutzernamen, Servernamen oder
freie Inventarbeschreibungen angewendet werden.
