# Ersten Administrator initialisieren

```bash
./cve_mon setup
./cve_mon start
./cve_mon health
.venv/bin/python scripts/security/bootstrap-admin.py --username administrator --email admin@example.org
```

Bei einer separaten Instanzkonfiguration für das Bootstrapwerkzeug
`CVE_ENV_FILE=/etc/cve-monitor/server.env` setzen. Docker-sudo nur verwenden,
wenn dieser Zugriff eingerichtet und erforderlich ist. Der aktuelle Einstieg
ist in der [Bedienungsanleitung](../bedienungsanleitung.md) beschrieben.
Benutzername und E-Mail-Adresse im Beispiel anpassen. Das Passwort wird interaktiv
mit verdeckter Bestätigung gelesen. Automation alternativ mit
`--password-file` und einer privaten Datei, 0400/0600, regulär, kein Symlink. Kein Passwortargument,
Standardpasswort, öffentliches Bootstrap oder automatische Kontoanlage beim Deployment.
Das Werkzeug verwendet ausschließlich den lokalen Operator-Kontext cve_migrator und eine
eng begrenzte native Funktion; Runtime erhält keine Bootstrapberechtigung. Advisory-Lock
verhindert zwei erste Administratoren. Auch ein archivierter vorhandener Admin verhindert
gewöhnliches Re-Bootstrap; Wiederherstellung benötigt einen bewusst geprüften Operatorplan.

Das neue aktive Konto ist mit der vorhandenen Systemrolle admin verknüpft.
Login mit Passwort liefert eine vollständige Session. MFA ist für alle Rollen optional
und kann unter Einstellungen → Kontosicherheit aktiviert oder deaktiviert werden.
Bei Aktivierung TOTP bestätigen und einmalige Recovery-Codes sicher verwahren. Audit dokumentiert die Initialisierung. Der reguläre lokale
Entwicklungsstack wird ohne automatisch erzeugtes Administratorkonto abgenommen.
