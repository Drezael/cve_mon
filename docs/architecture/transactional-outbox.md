# Transactional Outbox und Consumer-Idempotenz

Outbox.emit(session, EventEnvelope(...)) schreibt mit der fachlichen Änderung in
derselben bestehenden Transaktion. Kein eigener Commit, keine Netzwerkverbindung.
Erst nach Commit kann eine Zustellung reserviert werden; Rollback entfernt Effekt,
Event und zugehörige Zustellungen. Ereignisse sind unveränderlich.

Event-ID, Typ/Version, aus der Produzentenrolle gebundene Quelle, Entität/Version,
DB-Zeitpunkt, Korrelations-ID, Idempotenzschlüssel und validierte Nutzdaten bilden den
Vertrag. Gleiche Source/Idempotenzanforderung liefert das vorhandene Event; Konflikte
werden abgelehnt. Keine Ziel-URL oder ausführbare Steuerfelder aus Daten.

## Zustellung

Registrierte event_routes/delivery_targets erzeugen beim Schreiben die persistenten
Zustellungen. Die SQL-Registry enthält ausschließlich IDs, Aktivierung und Retrylimits,
keine URLs/Credentials. Die private Dienstkonfiguration bindet die ID an überprüftes
HTTPS und Token-/CA-Dateien. Standardmäßig keine Ziele oder Routen aktiviert.
Neue Routenkonfiguration liefert alte Events nicht unbeabsichtigt nachträglich aus.

Dispatcher reserviert fällige Zustellungen mit SKIP LOCKED, committet die Lease und
liest das Event; danach HTTPS ohne gehaltene Zeilenlocks. Nur 2xx bestätigt die
Annahme. Netzwerk/Timeout/429/5xx werden begrenzt wiederholt, Redirect/401/403/sonstige
4xx dauerhaft abgelehnt. Auch Bestätigungen und Recovery sind durch Fence geschützt.
Alle Versuche mit Zeit, Epoch, Dauer und stabiler Fehlerkategorie bleiben gespeichert.

Zustände: pending/retry_pending → running → delivered/retry_pending/failed.
HTTP-Annahme ohne gespeicherte DB-Bestätigung kann eine doppelte Zustellung erzeugen.
Idempotency-Key ist die unveränderte Event-ID. Keine Exactly-once-Behauptung für HTTP.

## Entitätsreihenfolge

Für requires_order gilt Ordnung pro Quelle + Entitätsart + Entitäts-ID + Ziel.
Produzenten serialisieren die Entitätsversion mit einem transaktionalen Advisory-Lock;
Versionen müssen steigen. Dispatcher hält spätere Versionen zurück, solange ein
älteres Event nicht delivered ist. Ein endgültiger Fehler blockiert diese Teilfolge
bis zur ausdrücklich autorisierten Wiederaufnahme; andere Entitäten bleiben parallel.
Keine globale Reihenfolge; unordered Eventtypen können unabhängig zugestellt werden.

## Consumer

begin_consume(session, consumer, event_id, fingerprint=None) prüft registrierten
Consumer, DB-Rolle und Eventtyp. Der immutable Outbox-Datensatz ist die maßgebliche
Identität; optional wird ein zusätzlich übergebener Fingerprint abgeglichen.
Unique(consumer,event_id) und Business-Effekt teilen eine Transaktion. Fehlversuch
rollt auch die Markierung zurück; konkurrierende Duplikate führen nur einmal zum
entsprechend implementierten DB-Effekt. Authentifizierte Annahme und fachliche
Payloadvalidierung bleiben Aufgabe des jeweiligen späteren Consumers.
