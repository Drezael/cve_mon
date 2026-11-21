# Ergebnisstatus

| Status | Aussage im angegebenen Kontext |
|---|---|
| affected | Identität, Version und Voraussetzungen bestätigen Betroffenheit |
| not_affected | Auswertbare Evidenz bestätigt Nichtbetroffenheit der geprüften Komponente |
| potentially_affected | Relevanter Bezug, aber Vergleich, Kontext oder Quellenkonflikt offen |
| unknown | Entscheidende Daten oder Abdeckung fehlen |
| not_applicable | Beispielsweise offiziell ausgeschlossene rejected/withdrawn CVE |

Phase 0 kennt im Legacy-Modell fixed, under_investigation und not_evaluable. Diese Werte
werden nicht umgedeutet. Die neue versionierte Resultatstruktur verwendet die fünf
expliziten Phase-17-Werte. Es gibt keine implizite Migration alter Findings.

Mindestens eine bestätigte Komponente kann das Aggregat affected machen. Gleichwertige
widersprüchliche Belege derselben Komponente ergeben potentially_affected mit vollständigem
Konflikt. Ein negatives Paket allein entwarnt keinen Server. Ohne vollständigen Nachweis
aller relevanten Kontexte bleibt das Aggregat unknown. Bei Inventar 1.1 wird deshalb keine
universelle globale Entwarnung behauptet. REJECTED ist ein Lebenszyklusausschluss,
kein Versionsnachweis. Jobstatus, Risiko und Betroffenheit bleiben getrennt.
