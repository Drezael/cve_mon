# Serverinventar hochladen

Unter **Server → Serverinventar hochladen** eine JSON-Datei auswählen und einreichen.
Format 1.2 legt neue Server anhand der Hostdaten automatisch an; bekannte Monitoring-IDs
führen zu einem neuen Inventarstand desselben Servers. Der Uploader erhält automatisch
Zugriff auf selbst angelegte Server. Es gibt eine gemeinsame Rollenberechtigung
`server:inventory:manage` statt einer weiteren Freigabe pro eigenem Server.

Die optionale Zuordnung zu einem Bestandsserver ist für die erstmalige Bindung einer neuen
Monitoring-ID gedacht. Formate 1.0 und 1.1 verwenden die interne Server-ID aus der Datei;
eine zusätzliche Auswahl ist nicht erforderlich. Die Originaldatei wird unverändert übertragen.
Browser-Uploads verwenden die angemeldete Sitzung und CSRF, keine technischen Tokens.

Die Annahme bestätigt die Speicherung und Serverzuordnung. Der Verarbeitungsstatus zeigt
den nachgelagerten Stand; n8n gibt Inventarverarbeitung und CVE-Abgleich frei. Bei unbekanntem
Übertragungsergebnis zuerst die Annahme prüfen. Wiederholungen behalten dieselbe Idempotenz-ID.

[Identität, Berechtigungen und Ansible](../../operations/server-onboarding.md)
