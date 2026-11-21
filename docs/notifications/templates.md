# Versionierte deutsche Vorlagen

Zwei gemeinsame Layouts (finding und digest) tragen versionierte Betreff-, Text- und
HTML-Inhalte. Die konkrete Ereignisart und die minimierten fachlichen Felder bestimmen
die jeweilige Meldung. Initiale Layouts liegen zusätzlich in configuration/notifications/templates/de.
Ein Intent referenziert die tatsächlich zu verwendende immutable Templateversion.

Nur title, items und link sind zulässige einfache Platzhalter. Der Betreff erlaubt nur
den einzeiligen Titel. HTML-Tags sind auf p/a/ul/li/strong/br/h2 begrenzt; einziges Attribut
ist der feste Dashboard-Link. Keine Skripte, frei ausführbaren Ausdrücke, Anhänge, Bilder,
Trackingpixel oder externen Ressourcen. Alle dynamischen HTML-Werte werden escaped.
Header und ASCII-Envelopes werden separat validiert. MIME enthält text/plain und text/html.

Maildaten: Event, CVE, Serverbezeichnung, Finding-ID, aktueller Lifecycle und Priorität,
verfügbare CVSS-/KEV-/frische EPSS-Signale, Erkennungszeitpunkt und Datenfrische. Keine
vollständigen Inventare, Zugangsdaten oder Sitzungsparameter. HTTPS-Links nutzen nur den
fest konfigurierten Dashboard-Origin und enthalten keine Tokens.
