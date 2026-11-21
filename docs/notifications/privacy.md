# Datenminimierung und Aufbewahrung

Intents speichern Referenzen und technische Zustände, keine vollständigen Finding-Kopien,
Inventare oder gerenderten MIME-Nachrichten. Adressen werden beim Submit aus der aktuellen
Benutzerregistrierung gelesen. n8n erhält Run-/Request-Referenzen und technische Ergebnisse.
Erfolgreiche und fehlerhafte Ausführungspayloads werden nicht gespeichert; Pruning begrenzt
verbleibende n8n-Ausführungsmetadaten auf sieben Tage und maximal 1000 Ausführungen.

Fachliche Historien bleiben append-only und werden nicht von n8n-Pruning gelöscht. Die
initiale Fachaufbewahrung erfolgt ohne automatische Löschung; eine spätere organisatorische
Löschfrist benötigt eine eigene geprüfte Migration bzw. ein Retention-Verfahren mit FK-/
Auditprüfung. Es wird keine gesetzliche Standardfrist erfunden. Betriebslogs rotieren.
