# Pipelineintegrität Phase 23

Importer und Enricher verwenden feste Quellen, geschlossene URL-/Redirect-/Archiv-/Dekompressionsgrenzen, Größen- und Zeitbudgets sowie Envoy ohne Direktfallback. Rohrevisionen und Quellenprovenienz bleiben unverändert. Matching bewahrt Debian/Ubuntu/RPM-/PURL-/CPE-Semantik und Unknown bei unzureichender Evidenz. Es wird keine Kandidatenheuristik zur Beschleunigung geändert.

Inventory-, Matching-, Finding- und Notificationworker behalten Jobleases, Heartbeats, Fencing, atomare Publikation und persistente Deduplizierung. Findings behalten Episoden, Reopening, Triage und technische Betroffenheit trotz Risikoausnahme. SMTP-Ungewissheit bleibt ein eigener Zustand und kein Zustellerfolg. Empfängerrechte werden unmittelbar vor Versand erneut geprüft. Statusalarme nutzen dieselbe kontrollierte Kette. Nachweis: vollständige Pipeline-, Worker- und Statusregression, nicht nur gemockte Fachfunktionen.
