# CISA KEV im Enrichment

Es werden ausschließlich persistierte Phase-15-Daten verwendet. Die Quelle ist der letzte
vollständig abgeschlossene Kataloglauf mit konkreter Katalogrevision und Mitgliedschafts-
beobachtungen. Ein teilweiser neuer Lauf ersetzt diese Grundlage nicht.

Aktueller Status im Read-View (kev_status): present, absent oder unknown. Ohne vollständigen oder bei veraltetem Katalog gilt
unknown, niemals pauschal absent. Standardalter maximal 72 Stunden, konfigurierbar innerhalb
geprüfter Grenzen. Die unveränderliche Revision beschreibt die Mitgliedschaft ihres konkreten Katalogs.
Deren fachlicher Inhalt bleibt deterministisch und enthält keine ablaufende Uhrzeitbewertung.
Der Current-Enrichment-View leitet daraus den altersgeprüften kev_status sowie kev_is_current ab; Verbraucher
müssen dieses Flag prüfen, da historische Revisionsaussagen nicht nachträglich umgeschrieben
werden. Das Flag prüft auch, ob die referenzierte Katalogrevision noch zum aktuellen vollständigen
Stand gehört. Ein neuer Katalog wird über kontrollierten Reconcile nachverarbeitet.

Bei nativer V5-JSON-Speicherung liest der Findings-Dienst den aktuellen KEV-Status über
`cve.kev_risk(identity)` direkt aus dem letzten vollständigen Katalog. Hier gilt eine
Frischegrenze von 72 Stunden. Die V5-Dokumente und ihre unveränderlichen Revisionen
werden dabei nicht umgeschrieben. Jeder vollständige KEV-Lauf stellt über n8n einen
paginierten Auftrag `findings.refresh_priority` bereit, auch bei unveränderten
Katalogdaten. Bestehende Findings erhalten damit den aktuellen KEV-Status und werden
nach der geltenden Prioritätsregel neu bewertet; ein Vollscan aller CVEs ist unnötig.

Der zentrale n8n-Updateauftrag darf `cve_list` und optional `cisa_kev` enthalten.
Für die Aktivierung müssen die persistente Importer-Konfiguration (einschließlich
API-Kopie), `automation.workflow_settings.source_config` und die Quellenfreigabe in
`cve.sources` übereinstimmen. V5 verwendet weiterhin Git; EPSS kann über den separaten
Schalter `epss_enabled` ergänzt werden (siehe [EPSS-Betrieb](../operations/epss-sync.md)).
Die regelmäßige Aktualisierung und der Dashboard-Button verwenden dieselbe n8n-Queue.

dateAdded, dueDate, knownRansomwareCampaignUse, Vendor/Product/Action/Notes bleiben in der
provenienzgebundenen Entry-Aussage erhalten. Unknown bei Ransomware wird nicht No.
Die CISA-Frist ist keine allgemeine rechtliche Betreiberpflicht. KEV erzeugt weder Findings
noch eine Behauptung über kompromittierte Server.
