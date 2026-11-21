# Benachrichtigungssystem

Seit Migration `00040_workflow_control` steuert n8n die gesamte Anwendung über einen
zentralen Plattformworkflow und acht Unterworkflows. Die sechs Versandworkflows bleiben
aktiv. Acht physische Container enthalten drei eigene Anwendungsprofile und unveränderte
Herstellerimages. Die privaten TLS-Steueraufrufe verwenden schrittgebundene Credentials;
die Kontroll-API erhält dafür eine eigene eingeschränkte DB-Identität.
Siehe [Workflow-Graph und Betrieb](../../workflows/n8n/README.md).

## Historischer Aufbau aus Phase 19

cve-notification und cve-api 0.19.0 verwenden cve_common 0.7.0. n8n 2.44.7 läuft als
zweiter neuer interner Dienst im Regular Mode. Alle dreizehn Dienste verwenden bestehende
Netzwerke. Die Datenbank cve_monitoring bleibt fachlich führend; n8n_app kann ausschließlich
auf seine eigene n8n-Datenbank zugreifen. Es gibt keinen Redis, Broker oder weiteren Relay.

Migrationen 00026/00027 erweitern automation. Die alte notification_deliveries-Tabelle
bleibt als Legacy-Vertrag erhalten; neue Intents, Versuche, Resultate und Historien sind
getrennte fachliche Objekte. Finding-/Matching-/Inventar-/CVE- und administrative Daten
werden von notification ausschließlich gelesen. n8n besitzt keine Fach-DB-Credentials.

Finding-Outbox → bestehender PostgreSQL-Job → validiertes Ereignis → versionierte Regel
und aktuelle Empfängerrechte → Intent → referenzbasierter n8n-Webhook → interne Claim-/
Execute-API → erneute Prüfung → persistenter Submit-Marker → Python STARTTLS/mTLS →
Postfix-Queue → vorhandener Envoy-TCP-Pfad → freigegebener Smarthost. Der interne Dienst
ist TLS-geschützt und hat keine Hostports. Die Browserverwaltung bleibt in cve-api.

Normale Regeln sind anfangs deaktiviert. Die bestehende geschlossene Postfix-Policy und
Envoy-Freigaben werden bei der Installation nicht geöffnet. Vollständige Versandtests
verwenden ausschließlich eigene Projekte, CA-Zertifikate, synthetische Empfänger und Sink.
Siehe notifications/, n8n/, smtp/ sowie development/phase-19-acceptance.md.

Seit Migration 66 ist eine eigene Regel für neue Findings aktiv: Das Ereignis
`finding.created` benachrichtigt den Benutzer, der den betroffenen Server angelegt
hat (`recipients=server_owner`), unabhängig von der Priorität und ohne vorherige
Bearbeiterzuweisung. Andere berechtigte Benutzer oder Administratoren erhalten
über diese Regel keine Kopie. Die Regel ist in der Administration bearbeitbar.
Persönliche Empfängeradressen, SMTP-Auswahl, Ruhezeiten und Benachrichtigungspräferenzen
werden weiterhin berücksichtigt. Ohne persönliche Empfängerliste gilt die Adresse
im Benutzerkonto; der SMTP-Transport verwendet die bestehende persönliche beziehungsweise
instanzweite Konfiguration.

Die vorhandene Ereignis- und n8n-Queue steuert Entscheidung und Zustellung. Eine
erneute Prüfung desselben Findings erzeugt keine neue `created`-Meldung. Wird die
Risikobewertung vor Verarbeitung des Erstellungsereignisses aktualisiert, bleibt
dieses für dieselbe noch offene Finding-Episode gültig. Alte Episoden werden nicht
erneut gemeldet. Direkt vor dem SMTP-Versand werden Benutzerstatus, Leseberechtigung,
Serverzuordnung und aktuelle Präferenzen erneut geprüft. Ereignisbelege, eindeutige
Benachrichtigungsidentitäten und die vorhandenen Zustellungsbelege verhindern
ungeprüfte Mehrfachzustellungen.

Die lokale Entwicklungsinstanz prüft die internen SMTP-Zertifikate stündlich über
den bestehenden Konfigurationsdienst. Vor Ablauf werden die Zertifikate mit den
vorhandenen Schlüsseln erneuert, die Fingerabdruckfreigabe angepasst und Postfix
nativ neu geladen. Der Benachrichtigungsdienst liest die TLS-Dateien bei jedem
Versand neu, sodass hierfür kein Prozess- oder Containerneustart nötig ist.
Produktiv bereitgestellte Zertifikate bleiben extern verwaltet. Vor der SMTP-DATA-
Phase fehlgeschlagene Verbindungen bleiben als wiederholbare Zustellungsversuche
in der Datenbank gespeichert; unklare DATA-Ergebnisse werden weiterhin nicht
ungeprüft erneut gesendet.

## Serverberichte und Wochenberichte

Migration 67 ersetzt die einzelnen Finding-Mails durch Serverberichte. Neue
`finding.created`-Ereignisse werden pro Server und Scan-Korrelation zusammengefasst.
Ein Bericht wird erst vorbereitet, wenn Matching, alle Seiten und Worker sowie die
Finding-Veröffentlichung abgeschlossen sind. Die Abschlussprüfung liefert über eine
begrenzte Datenbankfunktion nur Statusinformationen; der Notification-Dienst erhält
keinen allgemeinen Zugriff auf die Aufträge anderer Dienste. Fehlgeschlagene Scans
führen zu einem sichtbaren fehlgeschlagenen Bericht, nie zu einer unvollständigen Mail.
Bei überlappenden Scans prüft der Versand die Abschlussbedingung erneut und wartet
bei Bedarf weiter. Ein erneuter Scan ohne neue Findings erzeugt keine Scanmeldung.
Der Serverbericht enthält alle aktuellen offenen Findings des betreffenden Servers,
auch solche, die bereits vor dem auslösenden Scan bekannt waren.

`automation.mail_report_schedules` speichert pro Benutzer Aktivierung, Wochentag,
Uhrzeit, IANA-Zeitzone und nächsten Termin. Der Standard ist Montag um 09:00 Uhr
in Europe/Berlin. Die wöchentliche Ausführung erfolgt über die bestehende, von n8n
freigegebene Notification-Maintenance. Ein ausgefallener Termin wird einmal
nachgeholt, ohne jede versäumte Woche als weitere Mail abzuarbeiten.

Unter „Meine Einstellungen“ kann der Benutzer den Termin ändern oder einen Bericht
sofort anfordern. Der Request landet als `reports.scan` in der persistenten n8n-Queue;
erst n8n legt die Matching-Aufträge an. Der Wochenbericht ist eine gemeinsame Mail
für alle aktuell berechtigten verwalteten Server. Er enthält auch Server ohne
Findings sowie Server ohne Inventar mit einem ausdrücklichen Hinweis auf den
fehlenden Inventarstand. Vor dem Versand werden vorhandene Inventare neu geprüft;
dies stößt keine zusätzliche SSH-/Ansible-Erfassung an. Auch bei sofort angeforderten
Berichten wird auf die vollständige Scanverarbeitung gewartet.

Zeitplanung, Berichtsanfragen, zugehörige Server und Mailreferenzen sind dauerhaft
in PostgreSQL gespeichert. Idempotenzschlüssel verhindern doppelte Anfragen bei
Verbindungsabbrüchen. Benutzer- und Serverberechtigungen werden beim Start und
Versand erneut geprüft. Empfängeradressen und die persönliche beziehungsweise
instanzweite SMTP-Konfiguration werden weiterverwendet. Sofort ausdrücklich
angeforderte Berichte werden nach dem Scan auch während persönlicher Ruhezeiten
versendet; automatische Berichte berücksichtigen diese Ruhezeiten.

Die Weboberfläche fasst die technischen Statuswerte affected und potentially_affected
als „Betroffen“ zusammen; Detailnachweise und Matching-Ergebnisse bleiben erhalten.
Der Filter „Betroffen“ umfasst beide Ergebnisse. Die Bedrohungsanzeige zeigt die
Gefahrenstufe anhand von CVSS, aktueller KEV-Mitgliedschaft, frischen EPSS-Daten und
der geltenden Finding-Priorität. Fehlende oder veraltete Werte werden nicht als
Entwarnung interpretiert.

Mehrere CVE-Ereignisse desselben laufenden Serverscans werden auch bei unterschiedlichen
Workflow-Korrelationen in einem Bericht gesammelt. `automation.mail_report_contexts`
verfolgt diese Verarbeitungskontexte; die Scanbarriere wartet auf alle zugehörigen
Matching-, Finding- und Ereignisaufträge. Fehlgeschlagene Scans erzeugen keinen
unvollständigen Bericht.

Große Berichte werden vollständig als komprimierter Anhang derselben Mail versendet.
Der Mailtext enthält dann die Serverübersicht; die vollständige CVE-Liste bleibt
im Anhang erhalten. Ein überschrittenes Versandlimit wird als Fehler gespeichert,
statt CVEs stillschweigend wegzulassen.
