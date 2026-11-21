# Dashboard

Phase 20 stellt die lesenden Ansichten bereit. Phase 21 ergänzt schreibende Verwaltungsdialoge im selben Frontend.

- [Architektur](../architecture/dashboard-architecture.md) und [Navigation](information-architecture.md).
- [Anmeldung und MFA](authentication.md), [Berechtigungen](authorization.md), [Sicherheit](../security/dashboard-security.md).
- [Kennzahlen](overview-metrics.md), [Server und Gruppen](servers-and-groups.md), [Findings](findings.md).
- [Benachrichtigungen](notifications.md), [Zugänglichkeit](accessibility.md), [Performance](performance.md).
- [Deployment](../operations/dashboard-deployment.md), [Abnahme](../development/phase-20-acceptance.md).

Verwaltung: [Architektur](administration/architecture.md), [Formulare](administration/forms.md), [Server](administration/server-management.md), [Gruppen](administration/group-management.md), [Sortierung](administration/manual-ordering.md), [Inventarupload](administration/inventory-upload.md), [Finding-Triage](administration/finding-triage.md), [Risikoausnahmen](administration/risk-exceptions.md), [Benutzer](administration/user-management.md), [Rollen](administration/role-management.md), [Server-ACLs](administration/server-acls.md), [Benachrichtigungen](administration/notification-management.md), [Audit](administration/audit.md).

[Mutationsverträge](administration/mutation-contracts.md), [Verwaltungssicherheit](../security/dashboard-administration-security.md), [Testmatrix](../testing/phase-21-test-matrix.md), [Phase-21-Abnahme](../development/phase-21-acceptance.md).

Phase 22 ergänzt [Status und Betriebsdiagnose](../status/frontend.md) unter `/status`: Übersicht mit `deployment:status:read`, Detaildiagnose mit `deployment:diagnostics:read`, Wartung mit `deployment:maintenance:manage` und frischer MFA-Bestätigung. [Architektur](../architecture/statuspage-architecture.md), [Sicherheit](../security/statuspage-security.md), [Abnahme](../development/phase-22-acceptance.md).

Die Übersicht unterscheidet jetzt zwischen admin und normalen Benutzern: Nur admin sieht CVE-Datenbanksteuerung und n8n-Zeitplan. Reguläre Konten sehen ihre berechtigten Kennzahlen, Inventarqualität, Verteilungen und den Finding-Verlauf. Aktualisierung und Zeitplanänderung sind auch serverseitig an die Rolle admin gebunden.

## Server bearbeiten und prüfen

In **Server** öffnen Sie über **Bearbeiten** direkt die Stammdatenmaske. Speichern und Abbrechen führen zurück zur Serverübersicht. Gruppenzuordnungen, automatische Erfassung und Löschen befinden sich unter den weiteren Servereinstellungen. Eigene Server können von ihrem Eigentümer bearbeitet und gescannt werden; Administratoren können diese Aktionen für alle sichtbaren Server ausführen. Reine Lesefreigaben erlauben keine Änderungen.

**Scan** legt einen dauerhaften `matching.evaluate_snapshot`-Auftrag für das aktuelle gespeicherte Inventar an. n8n gibt ihn in der bestehenden zentralen Queue frei. Dabei wird der vollständige CVE-Bestand geprüft, keine neue SSH-Abfrage ausgelöst. Derselbe Idempotenzschlüssel erzeugt keinen doppelten Auftrag. Ohne verarbeiteten Inventarsnapshot ist der Button deaktiviert.

Die **Worker-Ausführungsqueue** bewertet wartende Arbeit und verlorene Leases. Fehlgeschlagene abgeschlossene Aufgaben bleiben in den Diagnosezahlen und Protokollen erhalten, markieren die funktionierende gemeinsame Queue aber nicht als gestört. Dienstbereitschaft und Datenfrische werden weiterhin gesondert geprüft. Fehlgeschlagene Löschungen werden nicht automatisch wiederholt.
