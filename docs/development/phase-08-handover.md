# Übergabe an Phase 9

Freigegeben ist die technische lokale Authentifizierung in cve-api 0.8.0. Für Fachrouten
wiederverwendbare authenticated_user-Dependency; prüft aktive serverseitige vollständige
Session, Zeiten/Versionen, Widerruf und aktuelle MFA. Kein RBAC allein aus Rollenheadern.
Phase 9 ergänzt Benutzer-/Rollen-/Objektverwaltung, Schutz des letzten Administrators,
autorisierte Faktorverwaltung und Widerruf durch Erhöhung des vorhandenen auth_version.

Kritische Aktionen benötigen aktuelle sessiongebundene einmalige Reauthentifizierung,
bei bestehender MFA mit frischem Faktor. Passwortänderung/Reset widerrufen alle Sessions.
Verwaltete native Rollen nur in expliziten getrennten Datenbankkontexten verwenden.
Der Haupt-API-Readerpool wird nicht auf eine mächtigere Rolle umgeschaltet.

Phase 10 ergänzt Fachberechtigungen, Phase 11 trennt Browser-Session und technische
mTLS-/Upload-Tokens. Phase 19 integriert einen tatsächlich autorisierten unabhängigen
Reset-/Benachrichtigungskanal; öffentliche Resetendpunkte bleiben bis dahin geschlossen.
Dashboard-UI/Bedienoberflächen folgen Phase 20–21. Produktions-PKI, Keybackup, Retention-
Archiv, Last-/Timing-/Phishinguntersuchungen werden in Betriebs-/Phase-23-Prüfungen vertieft.

[API-Vertrag](../../contracts/api/authentication.openapi.yaml), [Architektur](../architecture/authentication.md),
[Bedrohungsmodell](../security/authentication-threat-model.md), [Abnahme](phase-08-acceptance.md).
