# ADR-0037: Persistente Benachrichtigungen und eingeschränkte n8n-Orchestrierung

Status: angenommen, 08.11.2026.

Finding-Ereignisse können mehrfach auftreten. Workflowerfolg und SMTP-Zustellung sind
verschiedene Tatsachen; ein verlorenes SMTP-250 lässt sich nicht durch einfaches Job-Retry
in garantierte Einmalzustellung verwandeln.

PostgreSQL bleibt für Intents, Regel-/Templateversionen, Empfängerentscheidungen, Rate Limits,
Versuche und append-only-Historie führend. Vor Netzwerk-I/O werden submitting, Attempt und
Fencing-Token committed. Nach unklarer Übergabe wird kein automatischer Resubmit erlaubt.
Aktuelle Benutzer-/ACL-/Regelprüfung erfolgt vor jeder tatsächlichen Übergabe erneut.

n8n 2.44.7 verwendet ausschließlich seine eigene PostgreSQL-Datenbank im Regular Mode.
Sechs versionierte, interne Workflows übergeben nur gebundene Referenzen. HTTP-Header-
Credentials liegen verschlüsselt in n8n; SMTP und Empfängerermittlung bleiben in Python.
Die Editoroberfläche ist deaktiviert, Verwaltung erfolgt durch die autorisierten CLI-Werkzeuge.
Keine Fach-DB-Credentials, SMTP-, SQL- oder Code-Nodes und keine Hostports für n8n.

Der bestehende Postfix-/Envoy-TCP-Pfad bleibt unverändert. Relayannahme, Smarthostannahme,
Bounce und verifizierter finaler Zustellnachweis sind getrennte Zustände. Passive eigene
Postfix-Queue-/Logbeobachtungen und privilegierte attestierte Nachweise können sichere
Reconciliation liefern. Fehlende Nachweise bleiben unbekannt. Die initialen normalen
Benachrichtigungsregeln und Mailfreigaben bleiben geschlossen.

Folgen: zwei additive Migrationen, zwei private Container, eng begrenzte interne Service-
Schnittstellen und die bestehende Browser-API. Keine zusätzliche Queue, kein Redis,
keine Finding-/Quell-/Administrationsschreibrechte und keine unkontrollierten Empfänger.
