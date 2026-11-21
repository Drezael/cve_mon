# Benachrichtigungsverwaltung

Eigene Präferenzen: aktiv, immediate/digest, Priorität, Digest-Zeitraum, unterstützte Ereignisse, IANA-Zeitzone, endliche Ruhezeit und Wochentage. Pflichtmeldungen bleiben geschützt. Regelverwaltung nutzt nur die endlichen Phase-19-Felder, neue UI-Regeln starten deaktiviert. Aktive/alte Versionen sind getrennt paginiert lesbar und vergleichbar; vorherige Versandentscheidungen behalten ihre damaligen Versionen. Die aktuelle Regelliste ist ebenfalls paginiert. Vorlagen speichern Text, Betreff und erlaubtes HTML; unterstützt sind nur title/items/link. Vorschau verwendet die tatsächliche bestehende Template-Engine mit festen Testdaten, sendet keine Mail und rendert nur eine feste React-Tagliste ohne gefährliche HTML-Sinks oder aktive Links. Diese Fachansichten sind kein Postfix-/n8n-Admin, keine freien Testempfänger und kein ausführbarer Regelcode.


Die separate Seite **Mail-Einstellungen** ergänzt die berechtigte zentrale
SMTP-Serverkonfiguration einschließlich geschützter Zugangsdaten und Anwendung über
n8n. [Bedienung und Betrieb](../../operations/smtp-configuration.md).
