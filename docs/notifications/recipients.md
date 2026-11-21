# Empfänger und aktuelle Objektberechtigung

Ausschließlich registrierte security.users bestimmen die Empfängeradresse. Ein aktiver
Benutzer benötigt finding:read und explizites findings_read für den konkreten Server oder
die bestehende Adminrolle. Servergruppierung und Primärgruppe erteilen keine Rechte.
Zuständigkeit allein reicht ebenfalls nicht. Archivierte Server erhalten keine neuen Mails.

Vor SMTP werden Benutzerstatus, aktuelle Adresse, erlaubte Empfängerdomain, aktuelle ACL,
Regel und Finding erneut geprüft. Adressen aus CVE-, Inventar-, Webhook- oder Freitextdaten
werden nicht verwendet. Die erste Implementierung unterstützt sichere ASCII-Mailadressen;
abweichende Formate erhalten invalid_recipient_address. Ein Datensatz und eine MIME-Mail
gehören jeweils zu genau einem Empfänger; weder CC/BCC noch ein freies send_mail existieren.
