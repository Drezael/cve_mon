# Incident Response Phase 23

| Szenario | Erkennen | Eindämmen/Wiederherstellen | Nachweis/Verantwortung |
|---|---|---|---|
| API-Token oder mTLS-Zertifikat verloren | Auth-/Uploadaudit, fremde Quelle | Token und Zertifikat sperren, gebundene Nachfolger, negative Altwertprobe | Betreiber und Sicherheitsverantwortlicher; Principal-/Server-/Korrelation erfassen |
| Session/Konto kompromittiert | Login-/MFA-/Mutationsaudit | Sessionwiderruf, Konto sperren, Credential-/Authversion, MFA-Wiederherstellung kontrolliert | Keine Notfall-Selbsteskalation; zweiter nutzbarer Admin |
| Unzulässige Rolle/ACL | Vorher-/Nachheraudit | Betroffenen Grant widerrufen, Sitzung invalidieren, erlaubte Objekte prüfen | Sicherheitsverantwortlicher; Actor, Objektversion und Grund erhalten |
| Manipuliertes Inventar | Parser-/Processorfehler, Provenienzhash | Annahmequelle sperren, Rohbeleg privat sichern, neue autorisierte Erhebung | Keine manuelle Historienüberschreibung oder falsche Entwarnung |
| CVE-/Matchingstörung | Statusalter, Queue, Quellenrevision | Egress/Quelle/Worker prüfen, gefenct erneut verarbeiten | Datenqualität UNKNOWN bis belastbarer Nachweis |
| Datenbank-/Diskstörung | Readiness/ENOSPC/Poolfehler | Ingestion begrenzen, Speicherpfad prüfen, verifizierten isolierten Restore vorbereiten | Betreiber; RPO/RTO und Lücke dokumentieren |
| Notification/SMTP-Ausfall | Queuealter, Übergabe unklar | Wiederanlauf mit Guards, unklare Quittung nicht blind wiederholen | Keine doppelte Sendebehauptung; Empfängerrechte erneut prüfen |
| Secret-Leak | Secret-Scanner/Logalarm | Betroffenen Wert widerrufen/rotieren, betroffene Artefakte isolieren | Keine Secretwerte in Tickets; Hash/Key-ID und Umfang dokumentieren |
| Datenmanipulationsverdacht | unveränderliche Evidenz/Audit/Backupvergleich | Schreibzugang begrenzen, Integritätsvergleich und autorisierten Restore vorbereiten | Sicherheitsverantwortlicher; Originalbelege erhalten |

Kein automatischer Reparatur-/Versandkanal wird ergänzt. Kontaktwege und Vertretungen legt der Betreiber vor Phase24 fest. Jede Reaktion endet mit Wirksamkeitsprobe, Audit und Ursachen-/Folgenbewertung. Keine Nachricht wird durch dieses Dokument automatisch versendet.
