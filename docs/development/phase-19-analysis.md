# Analyse Phase 19

Ausgangsbasis: Phase 18, API/Findings 0.18.0, Head 00025, elf eigene Container.
n8n und notification sind bisher lediglich Architektur-/Rollenplatzhalter. n8n_app ist
auf die separate Datenbank n8n begrenzt. Die bestehende notification_deliveries-Tabelle
ist ein Legacy-Modell mit pending/sent/failed und bleibt datenhaltend erhalten.

Die bestehende Outbox besitzt versionierte Finding-Referenzen, Producer-Grenzen,
Publikationsversionen und persistente PostgreSQL-Jobs mit Heartbeats/Lease-Fencing.
Sitzungen, MFA, CSRF, RBAC und findings_read-ACL werden wiederverwendet.
Empfängeradressen stammen ausschließlich von aktiven security.users; Gruppierung
ist keine Zugriffsfreigabe. Finding-, Matching-, Enrichment- und Inventardaten bleiben
für notification read-only. Im normalen Bestand sind keine Benutzer oder Findings.

Postfix Phase 5 setzt Clientzertifikate und explizite Sender-/Empfängerfreigaben ein.
Der tatsächliche Egress ist die bestehende kontrollierte TCP-Route über Envoy:1587,
kein angenommener HTTP-Proxy-Support im Postfix-Client. Die normale Policy bleibt
geschlossen. Transporttests erhalten eigene Projekte und synthetische Empfänger.

Risiken: Datenbank-Fencing allein verhindert keine SMTP-Duplikate nach unklarem DATA-
Ergebnis. Deshalb dauerhafter submitting-Marker vor Netzwerkzugriff, gesonderte
submission_uncertain-Recovery und keine blinden Retries. Relayannahme ist kein
Zustellnachweis. n8n erhält Referenzen, keine Nachrichteninhalte oder Fach-DB-Credentials.
