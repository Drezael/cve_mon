# Übergabe an Phase 10

Freigegeben sind verifizierter Principal, zentrale Engine, SQL-ACL-Filter und transaktionale
Administration. Phase 10 implementiert erst die eigentlichen Server-/Gruppen-/Primärgruppen-/
Sortiermutationen. Jeweils endliches Rollenrecht plus Objektentscheidung und erforderliche
Reauth im selben kontrollierten Kontext; keine alte effective_server_access-View als Browserfilter.

Phase 11 benötigt getrennt Browsercookie/CSRF/inventory:upload:dashboard + inventory_upload-ACL
oder technische mTLS-/Bearer-/Serverregistrierung + inventory:submit. Keine Maschinenrechte
in menschliche Rollen kopieren, keine Uploadwrites auf Gruppen oder Sortierung.

Fachservices prüfen unabhängig vom Router erneut; Principal nur transaktionslokal, nichtcachen.
Kritische Konto-/Rollen-/ACL-Widerrufe auth_version erhöhen/Sessions widerrufen. Änderungen
unter festgelegter Advisory-/Benutzerlockreihenfolge, Actor/Ziel und Outbox atomar auditieren.
Systemrollen nur über überprüfte versionierte Migrationen ändern. Neue Katalogeinträge vergeben
nicht automatisch neue DB-Rechte; Rollenmatrix/Seeds und Negativtests ebenfalls aktualisieren.

Benachrichtigungen/Activation Delivery folgen Phase 19, Verwaltungs-UI Phase 21. Großlast,
Retention- und physische Key-/Notfallprozesse werden betrieblich weiter geprüft.
[Architektur](../architecture/authorization.md), [Testmatrix](../testing/phase-09-test-matrix.md).
