# Regeln, Unterdrückung und Versandgrenzen

Rule ist ein geschlossenes Pydantic-Modell. Versionen werden angehängt, nicht überschrieben.
Filter: Ereignis, Mindestpriorität, Lifecycle, technische Bewertung, gültiger CVSS, frischer
EPSS und aktueller KEV. Fehlende Werte bleiben unbekannt. Prioritätsmeldungen erfordern
standardmäßig eine tatsächliche Erhöhung oder neue KEV-Aufnahme; priority_direction=any
muss ausdrücklich genehmigt werden. Eine bloße tägliche EPSS-Aktualisierung ist kein Alarm.

Empfängerstrategie: assignee, administrators oder authorized. Mindestpriorität high,
maximal zehn Versuche pro Empfänger/Regel/Stunde und 168 Stunden Aufschub sind dokumentierte
Regelvorgaben, keine gesetzlichen Fristen. Global höchstens 100 Anwendungsversuche pro
Empfänger/Stunde. Rate-Zähler liegen in PostgreSQL und überstehen Neustarts.

Ruhezeit, Digest und Benutzerpräferenzen bleiben persistent. mandatory verhindert eine
allgemeine Benutzerabmeldung; critical_bypass umgeht Digest/Ruhezeit nur bei ausdrücklich
aktivierter Regel. Risikoakzeptanz unterdrückt nur mit suppress_active_exception=true.
Begründete Suppression und zeitliches Deferral sind unterschiedliche Zustände. Überholte
Regelversionen oder inzwischen nicht mehr handlungsrelevante Alarme werden vor Submit
unterdrückt. Ausnahmevorwarnung nutzt exception_warning_hours (genehmigter Standard 24).
