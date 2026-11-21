# Matching Recovery

Bei verlorenem Lease verwirft der Fence den gesamten Fachcommit. Phase-7-Recovery überführt
abgelaufene Aufträge begrenzt in Retry oder terminale Fehler. Ein identischer erfolgreicher
Retry findet dieselbe Revision und publiziert sie nur, wenn die Eingabepointer noch passen.
Keine historischen Updates, keine automatischen Findings oder Servermaßnahmen.

Nach Container-/Hostneustart bei fehlender Readiness: eigenen PostgreSQL-Endpoint prüfen,
dann scripts.cve_matcher.manage guard beziehungsweise matching-up verwenden. Ein fremder
Namespace oder ein fremdes Compose-Projekt wird nicht verändert. Alte Proofdateien sind
bei neuem Namespace ungültig. Bei geändertem PostgreSQL-IP muss der Guard erneuert werden.

Nach DB-Ausfall stoppt der Worker seine aktive Bewertung und meldet fehlende Readiness;
begrenzte Recovery folgt nach Wiederverfügbarkeit. Nach behobenem permanentem Fehler kann
api_security den vorhandenen Phase-7-Replay verwenden. Ein kontrolliertes reconcile schließt
fehlende Kandidaten und veraltete Bewertungen. Keine automatische Vollverarbeitung beim Start.
Vor Migration Backup beider Datenbanken; Rollback nur über geprüften Restore, kein DROP.
