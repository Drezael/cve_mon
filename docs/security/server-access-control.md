# Serverzugriff

Server-UUID ist die einzige Objektidentität. Hostname, Gruppe, IP oder Anzeigename reichen
nicht. Funktionsrecht plus explizites passendes ACL-Flag; nur deklarierte Plattformadmin-
Leserechte bilden die dokumentierte Ausnahme. Verborgene Objekte werden 404, fehlende
Funktionen 403; fehlende/alte Session 401. Keine Zielinformationen in Problemantworten.

ACL-Ersatz maximal 100 Einträge und gemeinsames 8-KiB-Bodylimit; bekannte Rights, keine
Duplikate, Existenz-FKs, separate Set-Revision auch für leere ACL. Alte Versionen 409,
keine Teiländerung. Keine Gruppen-/Primärgruppen-/Sortierwrites durch diese Operation.
[SQL-Filter](../architecture/object-permissions.md).

Vorhandene Legacy-Sets mit mehr als 100 Freigaben benötigen Operatorprüfung (409),
bevor sie im normalen begrenzten Verwaltungsmodell angezeigt/ersetzt werden.
