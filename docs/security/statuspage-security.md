# Sicherheit der Statusüberwachung

Systemstatus ist ausschließlich für angemeldete Benutzer mit der Rolle `admin` sichtbar und zugänglich. Zusätzlich gelten die jeweiligen Status-, Diagnose-, Wartungs- und Neustartberechtigungen. Einzelne Statusberechtigungen ohne `admin` reichen nicht aus. Die Rollenprüfung gilt auch für direkte Seitenaufrufe und sämtliche menschlichen Status-API-Anfragen. Interne technische Healthprüfungen und n8n-Hintergrundabläufe bleiben unabhängig davon verfügbar. Das Navigationssymbol ist eine Aktivitäts-/Pulslinie.

Feste Prüfziele aus dem Katalog; kein URL-/Host-/SQL-/Shell-Input aus dem Browser. Die API übernimmt keine fremden Response-Bodies, Job-Payloads oder Mailadressen. Readiness und Fachfunktion sind getrennt. TLS ist verify-full; kein unsicherer Fallback. Interne HTTP-Healthendpunkte bleiben im bestehenden isolierten Netzwerk und werden nicht als freie Diagnoseproxys veröffentlicht.

status_probe ist kein Superuser und besitzt keine Fachschreibrechte oder Zugriff auf Benutzercredentials. Datenquellen sind feste gekapselte Aggregate. Rohmessungen sind für Laufzeitrollen nicht aktualisierbar; Retention ist eine begrenzte kontrollierte Funktion. Wartungsänderungen verlangen Session, MFA, CSRF, Step-up und Objektversion sowie unveränderliches Audit. Keine neue Berechtigung für Viewer. Statusalarme prüfen aktuelle Empfängerrechte vor Auftrag und erneut vor SMTP.

Die einzigen neuen beschreibbaren Dateimounts enthalten atomare, minimierte Eigenbeobachtungen von Envoy beziehungsweise Postfix. Keine Docker-Schnittstelle, kein zusätzlicher Netzwerkzugang. Alle übrigen Mount- und Netzwerkschranken werden durch den bestehenden Compose-Validator weiter geprüft. Keine eigenständige SMTP-Zustellung, keine Testmail und keine automatische Reparatur.


Die explizite Prozessneustartfunktion verwendet eine eigene nicht delegierbare
Administratorberechtigung. Der Browser darf ausschließlich feste Status-Dienst-IDs
übermitteln. n8n entscheidet über die Queue; ein bestehender Host-Agent führt nur
autorisierte Auftrags-UUIDs aus. Innerhalb des Containers wird ein Prozess neu
gestartet. Docker-Socket, freie Dockerziele und Shellbefehle werden keinem Dienst
oder n8n zur Verfügung gestellt. Infrastrukturcontainer werden nicht neu gestartet.


Der n8n-Health-Bridge besitzt nur zwei feste Prüfpfade, verifiziert TLS, folgt keinen
Redirects und gibt ausschließlich einen begrenzten Zustand zurück. Es gibt keinen
freien URL-Parameter und keine Weiterleitung von n8n-Antwortinhalten. Der SMTP-Client
verwendet den nur im internen Bridge-Netz registrierten Alias `cve-mail-submit` für
die TCP-Verbindung und behält `cve-mail-relay` als geprüfte TLS-Zertifikatsidentität.
