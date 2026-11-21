# Annahme, Historisierung und Idempotenz T00.03.05

Authentifizierung/Serverberechtigung werden vor Kenntnisgabe von Bestandsdaten geprüft.
Herkunft ansible_api oder dashboard_file, Actor und Empfangszeitpunkt vergibt ausschließlich
cve-api aus der geprüften Route/Identität; sie sind keine Felder im Inventar-JSON.
Beide Wege führen in denselben Annahmeprozess und cve-inventory-Job.

| Situation | HTTP / Annahme | Historie und Verarbeitung |
|---|---|---|
| Erstes gültiges Inventar, registrierter aktiver Server | 202 accepted | Snapshot, Receipt, Job und inventory.received atomar |
| Neue inventory_id desselben Servers | 202 accepted | Neuer unveränderlicher Snapshot; keine historische Löschung |
| Gleiche inventory_id und kanonisch gleicher Inhalt | 200 duplicate | Bestehender Job/Snapshot; neuer Receipt für den Übertragungsweg, kein zweiter Fachjob |
| Gleiche inventory_id mit anderem Inhalt oder server_id | 409 inventory_conflict | Kein Überschreiben, kein neuer Job |
| Älteres Inventar trifft später ein | 202 accepted, historical_only=true | Historisieren, aber keine Rücksetzung des effektiven Datenstandes |
| captured_at mehr als 5 min in der Zukunft | 422 invalid_timestamp | Ablehnen; Uhrzeit korrigieren und neue Erfassung durchführen |
| Teilinventar | 202 accepted | Positive Nachweise nutzbar, fehlende Pakete schließen keine Findings |
| Fehlgeschlagenes Inventar | 202 accepted | Erfassungsfehler historisieren, keine aktive Softwareliste ersetzen |
| Unbekannter oder nicht autorisierter Server | 404 server_not_found | Keine automatische Registrierung, keine Existenzoffenlegung |
| Deaktivierter oder archivierter Server | 409 server_inactive | Nur autorisierte administrative Wiederherstellung/Aktivierung kann dies ändern |
| Gruppen-/Sortierfeld, auch verschachtelt | 422 invalid_inventory | Kein Snapshot, keine administrativen Änderungen |
| Zielserver-ID des Dashboard-Formulars ungleich Datei | 422 server_identity_mismatch | Ablehnen, keine Umdeutung der Identität |
| Falscher Medientyp, zu groß, ungültiges JSON | 415 / 413 / 400 | Vor Annahme ablehnen |
| Kein mTLS / kein Token / falscher Scope | TLS-Ablehnung / 401 / 403 | Keine fachliche Annahme |
| Keine Sitzung / kein CSRF beim Dashboard | 401 / 403 | Keine fachliche Annahme |

Authentifizierung und aktueller Serverzustand werden auch bei Duplikaten geprüft. Bei
gleichzeitigem Erfassungszeitpunkt entscheidet die lexikographisch größere kanonische
inventory_id als deterministischer Tie-Breaker; bestehende Historie bleibt vollständig.
Eine neue Datei mit bereits verwendeter inventory_id und geändertem Inhalt ist kein Update.

## Kanonisierung v1

Hash ist SHA-256 über UTF-8-JSON mit rekursiv nach Unicode-Codepunkten sortierten Objektkeys,
kompakten Separatoren und unveränderten Zeichenfolgen (keine Unicode-Normalisierung).
Whitespace und Objektschlüsselreihenfolge sind irrelevant; Arrayreihenfolge und vollständige
Versionszeichenfolgen bleiben relevant. Der Vertrag enthält keine Gleitkommazahlen, doppelte
Keys sind verboten. Dies ist die hier definierte v1-Regel, keine behauptete RFC8785-Implementierung.
Transportmetadaten/Receipts werden nicht mitgehasht. Die globale UNIQUE inventory_id plus Hash
entscheidet atomar über Duplikat/Konflikt, auch bei parallelen und kanalübergreifenden Uploads.

## Transaktion und effektiver Datenstand

202 erst nach Commit des unveränderlichen Originaldokuments, Snapshots, Receipts, persistenten
Jobs und Outbox-Ereignisses. Antwort ist keine Bestätigung erfolgreicher Normalisierung.
Abbruch vor Commit: kein Erfolg; verlorene Antwort nach Commit: gleicher Upload kann gefahrlos
wiederholt werden. Normalisierung und anschließende Auswertung sind idempotent.

Snapshots besitzen captured_at und received_at. Der letzte Erfassungsversuch ist separat
vom letzten vollständigen Bereichsnachweis. Nur neuere vollständige Bereichsnachweise dürfen
Abwesenheit belegen; partial liefert ausschließlich positive Informationen, failed keine.
Effektive Sichten zeigen Herkunft/Snapshot und Alter jedes Bereichs. Alte oder fehlgeschlagene
Snapshots verdrängen keine neueren vollständigen Daten und schließen keine Findings.
Keine Upload-Transaktion, kein Trigger und kein Outbox-Consumer ändert Gruppen oder Sortierungen.
