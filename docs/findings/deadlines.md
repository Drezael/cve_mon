# SLA und Eskalation

Ohne freigegebene deadlines_hours-Policy bleibt due_at undefiniert. Eine konfigurierte Frist
beginnt beim serverseitigen Episodenbeginn; wiederholtes Matching oder eine Zuweisung setzt
sie nicht zurück. Eine frühere zulässige Frist wird bei Höherpriorisierung übernommen,
automatische Verlängerungen oder Löschungen bestehender Fristen sind ausgeschlossen.
Neue Episoden erhalten neue Fristen; geschlossene Episoden behalten ihre Historie.
CISA dueDate ist Quelleninformation, keine allgemein verbindlich angenommene Betreiberfrist.

check_deadlines verarbeitet begrenzte Batches. deadline_warning_hours muss ausdrücklich
konfiguriert sein. Approaching und overdue werden pro immutable Deadline und Stufe genau
einmal erfasst. Die Outbox übernimmt Ereignisse; keine E-Mail, kein SMTP, keine n8n-Pflicht.
Die Laufzeit plant alle 60 Sekunden einen persistenten Wartungsjob, sofern eigene Findings
existieren; der Intervall ist technisch konfigurierbar und keine fachliche SLA.
