# ADR-0036: Stabile Findings und autorisierte Verwaltung

Status: angenommen, 08.11.2026.

Ein Matching-Ergebnis bewertet einen konkreten Eingabestand. Ein Finding muss denselben
Server und dieselbe CVE über neue Snapshots, Enrichment-Revisionen und Wiederauftreten hinweg
zusammenhalten. Technische Bewertung und menschliche Bearbeitung benötigen getrennte Grenzen.

Wir erweitern die vorhandene Finding-Tabelle datenhaltend um model_version=2 und einen
partiellen eindeutigen Server/CVE-Schlüssel. Legacy-Komponentenbefunde bleiben erhalten.
Beobachtungen, Episoden/Closures und sämtliche Entscheidungen werden unveränderlich ergänzt.
Die Veröffentlichungsversion des Matchers bestimmt Aktualität; die Resultat-UUID allein ist
kein Deduplizierungsschlüssel. PostgreSQL sperrt die aktuelle Eingabebasis während der
Bewertung; Jobs, Finding, Audit und Outbox werden mit demselben Lease-Fence committed.

cve-findings verwendet eine eigene eingeschränkte Rolle und einen offline betriebenen
Container. Menschliche Entscheidungen laufen über die bestehende API und eng begrenzte
Datenbankkommandos mit aktueller Sitzung, Berechtigung, Objekt-Scope und erwarteter Version.
Privilegierte Entscheidungen benötigen frische MFA. Getrennte Outbox-Producer erhalten die
bestehenden Ereignisbesitzgrenzen.

Automatische Resolution bleibt ohne genehmigte Richtlinie und vollständigen aktuellen
Negativnachweis gesperrt. Der gegenwärtige Inventory-1.1-/Matching-Vertrag belegt keine globale
Negativabdeckung. Ein manueller Fehlalarmabschluss ändert deshalb keine technische Evidenz.
Risikowerte bleiben getrennt, fehlende Werte undefiniert. Fristen entstehen ausschließlich
aus expliziter Policy. Phase 19 kann kompakte Ereignisse nutzen; Phase 18 aktiviert keine
Benachrichtigungsziele und benötigt weder einen Broker noch n8n-Ausführung.

Folgen: ein zusätzlicher interner Worker, zwei additive Migrationen und neue API-Verträge;
keine Finding-Schreibrechte für Matcher oder Quellimporte. Historie, Recovery, Berechtigungen
und Datenbestand sind in der Phase-18-Abnahme mit nativen Prüfungen nachgewiesen.
