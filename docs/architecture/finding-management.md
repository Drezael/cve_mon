# Finding Management, Phase 18

cve-findings 0.18.0 verarbeitet Matching-Publikationen mit cve_common 0.7.0 und den
bestehenden PostgreSQL-Jobs. cve-api 0.18.0 liefert die geschützten Browserendpunkte.
Kein weiterer Broker und keine externe Kommunikation. Die Domain-Verträge des installierten
cve_findings-Pakets werden auch von der API verwendet; es gibt keine zweite State Machine.

Matching.created/replaced erzeugt im selben Outbox-Commit einen persistenten Finding-Job.
Der Worker prüft Schema, Quelle, Resultat und sämtliche Input-IDs, übernimmt ein Event-Receipt
und verarbeitet die stabile Server/CVE-Identität. Advisory-/Risikoereignisse erzeugen keine
neuen Findings. Publikationsversionen verhindern veraltete Überschreibungen; wiederverwendete
Resultat-UUIDs werden nicht allein als Duplikate behandelt. Resultat, Beobachtung, Audit,
Episode, Priorität, Frist und Outbox werden zusammen mit dem Lease-Fence committed.

Die Migrationen 00024/00025 erweitern die bestehenden Tabellen datenhaltend. Legacy-Befunde
bleiben model_version=1 und behalten ihre Komponentenidentität und alten Matching-Verweise.
Neue Befunde sind model_version=2 und verwenden einen eigenen partiellen Server/CVE-Unique-Key.
Die Legacy-CVE-Bindung bleibt als generierte Legacy-Spalte erhalten; neue Resultate sind per
zusammengesetztem Fremdschlüssel an die tatsächliche Server/CVE-Identität gebunden.

Eine globale Entwarnung aus Phase 17 wird nicht erfunden. Dessen aktueller Inventory-1.1-
Vertrag liefert keine exhaustive globale Negativabdeckung. Der Finding-Worker kann qualifizierte
künftige vollständige Nachweise auswerten; standardmäßig ist automatische Resolution deaktiviert.
Ein autorisierter scoped False-Positive-Abschluss bleibt eine manuelle Entscheidung und
ändert niemals die technische Betroffenheit. Phase 19 erhält ausschließlich kompakte Outbox-
Referenzen, keine direkten Nachrichten. Die Auslieferungsziele bleiben geschlossen.
