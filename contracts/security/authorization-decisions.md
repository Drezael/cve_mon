# Entscheidungsvertrag v1

Verified Principal → aktiver vollständiger Sessionkontext → explizites endliches Rollenrecht
→ erforderliche MFA → ggf. unveränderliche Server-UUID und eigener ACL-Scope → Zusatzpolitik.
Unbekannt bedeutet deny. Interner Decision enthält allow und neutralen reason; HTTP gibt
nur generische 401/403/404/409 aus. Mutationen mit CSRF, striktem Schema, aktueller Version
und ggf. kurzlebigem einmaligem Reauth. Kein Cache darf nach einem Commit alte Rechte nutzen.

Systemrolle admin hat deklarierte Plattformleserechte; Uploads bleiben explizit objektgebunden.
Gruppen und Primärgruppen vererben keine Browserrechte. Zusätzliche Rollen nur delegierbare
menschliche Aktionen. Maschinenidentitäten/Service-Pools bleiben getrennt.
