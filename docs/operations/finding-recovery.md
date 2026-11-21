# Recovery und Reconciliation

Ein verlorener Lease verwirft den gesamten Fachcommit einschließlich Audit und Events.
Phase-7-Recovery und begrenzte Retries gelten unverändert. Gleiche Source-Events und
Matching-Publikationen sind idempotent; historische verspätete Events ändern keine neuere
Finding-Basis. Reconcile ist ein ausdrücklicher Keyset-Job über aktuelle Matching-Pointer.

Bei PostgreSQL-Ausfall fehlen Readiness und zuverlässiger Claim; nach Wiederverfügbarkeit
führt die begrenzte Recovery fort. Nach Container-/Hostneustart bei neuem Namespace ist der
Guard erneut zu installieren: scripts.cve_findings.manage guard bzw. findings-up. Fremde
Container und Namespaces werden nicht verändert. Ein alter Proof allein öffnet keine Claims.

Permanente Fehler nach Prüfung mittels vorhandener api_security-Replay-Funktion behandeln;
keine direkte Manipulation historischer Zeilen. Vor normaler Migration beide Datenbanken
sichern. Rollback ausschließlich über geprüften Backup/Restore, keine destructive Downgrades.
