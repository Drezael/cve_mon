# Persistente Einstellungen

Erfolgreich gespeicherte Einstellungen werden serverseitig gehalten. PostgreSQL
verwendet den Bind-Mount `MOUNT_BASE/storage/<projekt>/postgres-data` unter
`/var/lib/postgresql`; darin
liegen sowohl `cve_monitoring` als auch die eigene Datenbank von n8n. Die drei
Anwendungscontainer haben ein schreibgeschütztes Dateisystem. Dauerhafte
Konfigurationen und Schlüssel werden aus projektgebundenen Hostverzeichnissen
unter `SECRETS_BASE` eingebunden.

| Bereich im Frontend | Dauerhafter Speicher |
| --- | --- |
| Benutzer, Passwörter, Rollen und Zugriffsrechte | `security.users`, `password_credentials`, `roles`, `role_permissions`, `user_roles`, `user_server_access`, `user_group_access` |
| Optionales MFA und Wiederherstellungscodes | `security.mfa_methods`, `security.recovery_codes`; Schlüssel in `SECRETS_BASE/services/<projekt>/auth-keys.json` |
| Server, Gruppen, Mitgliedschaften und Reihenfolgen | `inventory.servers`, `server_groups`, `server_group_memberships`; `dashboard.ungrouped_server_order`, `dashboard.order_versions` |
| Persönliche gespeicherte Ansichtspräferenzen | `dashboard.user_preferences` |
| Ansible-Verbindungen, Abfrageintervall, Mountpfade und bestätigte SSH-Hostkeys | `inventory.ansible_profiles`; verschlüsselte Zugangsdaten mit `SECRETS_BASE/services/<projekt>/ssh-keys.json` |
| Persönliche Benachrichtigungspräferenzen, Ruhezeiten und Versandform | `automation.notification_preferences` |
| Versandregeln und Vorlagen | `automation.notification_rules`, `automation.notification_templates` |
| Zentrale und persönliche SMTP-Profile, Empfänger und Transportauswahl | `automation.smtp_configs`, `automation.smtp_routes`; verschlüsselte Zugangsdaten mit `SECRETS_BASE/services/<projekt>/smtp-keys.json` |
| Automatische CVE-Updates und Aktualisierungsintervall | `automation.workflow_settings` |
| Pausierte und abgebrochene Workflow-Läufe | `automation.workflow_runs`; zugehörige Jobs und n8n-Aufträge in PostgreSQL |
| Finding-Richtlinien, Zuordnungen, Notizen, Bewertungen und Ausnahmen | `findings.policy_versions`, `active_policy`, `assignments`, `notes`, `reviews`, `exceptions`, `exception_decisions`, `mitigations` |
| Geplante Wartungsfenster | `status.maintenance_windows` |
| n8n-Workflow-Definitionen, Aktivierungsstatus und Zugangsdaten | Datenbank `n8n`, insbesondere `workflow_entity` und `credentials_entity`; Schlüssel in `SECRETS_BASE/n8n/<projekt>/config/encryption.key` |

## Mail-Konfiguration nach dem Wiederanlauf

Die aus freigegebenen SMTP-Profilen erzeugten Dateien liegen unter
`SECRETS_BASE/mail/<projekt>/state` und `secrets`. Native Postfix-Maps in `/run/postfix`
werden beim Start daraus neu aufgebaut. Persönliche Routing-Metadaten unter
`SECRETS_BASE/notifications/<projekt>/smtp-delivery.json` sind ebenfalls eingebunden.
Damit bleiben Empfänger, Absender, getrennte Zugangsdaten und die Wahl des
SMTP-Servers auch beim Ersatz der Container erhalten. Die native Mailqueue liegt
im Bind-Mount `MOUNT_BASE/storage/<projekt>/postfix-queue`.

Ein mit HTTP 202 bestätigter SMTP-Auftrag ist bereits in PostgreSQL gespeichert.
Sein Fortschritt bleibt über `automation.n8n_queue` und `automation.smtp_configs`
erhalten. Die Anwendung erfolgt weiterhin erst nach Freigabe durch n8n.

## Erstinitialisierung und Wiederanlauf

Nur eine ausdrücklich freigegebene Erstinitialisierung einer leeren Installation
legt die initialen n8n-Workflows an und aktiviert die zentrale Steuerung mit ihren
Anfangswerten. Beim Wiederanlauf werden vorhandene Zeitpläne, deaktivierte
Steuerung, deaktivierte Workflows, angepasste Definitionen und Zustellziele
beibehalten. Fehlende zentrale Workflow-Definitionen erfordern eine explizite
Reparatur; ein Start überschreibt keine vorhandenen Definitionen mit Vorlagen.

Der unterstützte Wiederanlauf über die vorhandenen Startcontroller stellt auch
die an den jeweiligen Netzwerk-Namespace gebundenen Schutzregeln und Startfreigaben
wieder her. Diese Freigaben sind Laufzeitdaten und werden je Containerstart erneuert.
Die gespeicherte fachliche Konfiguration bleibt dabei unverändert.

Datenbank- und Queue-Bind-Verzeichnisse sowie die eingebundenen Konfigurations- und
Schlüsselverzeichnisse gehören gemeinsam in die vorhandene Sicherung.

## Prüfung

`tests/orchestration/test_settings_persistence.py` speichert Änderungen über die
Dashboard-APIs in einer isolierten Installation. Anschließend werden PostgreSQL
neu gestartet und neu angelegt sowie die Anwendungscontainer ersetzt. Die Prüfung
vergleicht Konfigurationstabellen und n8n-Definitionen, kontrolliert die eingebundenen
Dateien, liest Einstellungen erneut über echtes HTTPS und entschlüsselt die
bestehenden SMTP- und SSH-Zugangsdaten. Auch absichtlich deaktivierte Einstellungen
müssen erhalten bleiben. Das laufende Entwicklungssystem wird für diese Prüfung
nicht neu gestartet.
