# Statusoberfläche

Systemstatus ist ausschließlich für angemeldete Benutzer mit der Rolle `admin` sichtbar und zugänglich. Zusätzlich gelten die jeweiligen Status-, Diagnose-, Wartungs- und Neustartberechtigungen. Einzelne Statusberechtigungen ohne `admin` reichen nicht aus. Die Rollenprüfung gilt auch für direkte Seitenaufrufe und sämtliche menschlichen Status-API-Anfragen. Interne technische Healthprüfungen und n8n-Hintergrundabläufe bleiben unabhängig davon verfügbar. Das Navigationssymbol ist eine Aktivitäts-/Pulslinie.

Vorhandenes React-/TypeScript-Frontend, neue lazy geladene /status-Routen. Übersicht, Dienstdiagnose, Pipelines, Störungsverlauf und Wartung. Status als Text und Symbol, Messzeitpunkt und Coverage sichtbar. Diagnoseverweise nur bei Diagnoseberechtigung. Rohmessungen und Wartung getrennt. Historische Status- und Zahlenpunkte werden ohne Interpolation gezeichnet; eine zugängliche Tabelle enthält dieselben Daten. Die Seite wird ausschließlich über den manuellen Aktualisieren-Button neu geladen. Die Hintergrundprüfung über n8n aktualisiert den serverseitigen Live-Cache unabhängig davon; sie löst kein automatisches Neuladen der Seite aus. Backendfehler entfernt die alte Anzeige und zeigt einen unbekannten aktuellen Zustand. Kein Storage von Sessions oder technischen Credentials.

Dienst- und Pipelinezeilen ordnen Neustartstatus-Texte vor dem einzelnen
Neustart-Button und danach dem Statuslabel an. Die Labels stehen in einer festen
rechten Spalte. Auf schmalen Bildschirmen steht der Text oberhalb; Button und
Label bleiben nebeneinander. Auch Zeilen ohne Neustartaktion nutzen dieselbe
Labelspalte.
