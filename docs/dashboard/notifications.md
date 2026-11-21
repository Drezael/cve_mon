# Benachrichtigungen

Die bestehenden Notification-APIs prüfen eigene Empfängeridentität, aktuellen Finding-Zugriff und Administrationsrechte serverseitig. Status und Historie bleiben unverändert. relay_accepted bedeutet Postfix-Annahme; upstream_accepted bedeutet Smarthost-Annahme; erst delivery_confirmed bezeichnet nachgewiesene Zustellung. submission_uncertain, suppressed und Fehler bleiben eigenständige Zustände. Details und Versuche sind paginiert. Keine SMTP-Funktion, kein n8n-Zugriff, kein Regel- oder Templateeditor und kein Versandtest im Browser.

Die Liste enthält CVE-/Finding- und Serverreferenzen sowie die aktuelle Finding-Priorität;
diese ist nicht die historische Versandpriorität. Bei Digests sind Einzelreferenzen null.
Historie und Versuche akzeptieren limit 1..100 und offset 0..100000, Standardlimit 50.
Die Oberfläche fordert jeweils 25 Einträge an. Rechteprüfung erfolgt weiterhin vor der
Datenabfrage und bei jedem Seitenwechsel erneut.
