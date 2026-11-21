# Persönlicher und zentraler Mailversand

Unter **Meine Einstellungen → Meine Mail-Einstellungen** (`/settings/mail`) legt
jeder Benutzer eine oder mehrere Empfängeradressen fest (maximal 20). Eine Adresse
pro Zeile; Komma und Semikolon sind ebenfalls möglich. Ohne persönliche
Konfiguration bleibt die E-Mail-Adresse des Benutzerkontos der Standard.

Die SMTP-Auswahl bietet zwei Möglichkeiten:

- **Zentralen SMTP-Server verwenden:** Der Administrator stellt den gemeinsamen
  Transport bereit. Seine Zugangsdaten bleiben für andere Benutzer unsichtbar.
- **Eigenen SMTP-Server verwenden:** Hostname, Port, Benutzername, Passwort und
  Absender gelten ausschließlich für diesen Benutzer. Ein eigener Transport
  funktioniert auch bei deaktiviertem zentralem SMTP. Fehler führen niemals zu
  einem stillen Wechsel auf den zentralen Server.

Unter **Meine Einstellungen → Benachrichtigungspräferenzen** bleiben Ereignisse,
Mindestpriorität, Versandform und Ruhezeiten persönlich einstellbar. Kontosicherheit
und optionales MFA liegen ebenfalls unter **Meine Einstellungen**. Alte Links auf
`/administration/account` und `/administration/preferences` werden weitergeleitet.

## Administration

**Administration → Zentrale SMTP-Einstellungen** (`/administration/smtp`) verwaltet
den gemeinsamen SMTP-Zugang und dessen Aktivierung. Die nicht delegierbare
Berechtigung `notification:smtp:manage` gehört standardmäßig nur zur Systemrolle
Admin. Systemweite Versandregeln und Vorlagen sowie Benutzer, Rollen und Audit
liegen im administrativen Bereich; jede Funktion prüft ihre eigene Berechtigung.
Persönliche Einstellungen gewähren keine administrativen Rechte.

Für beide SMTP-Arten gilt verpflichtendes STARTTLS mit Zertifikats- und
Hostnamenprüfung, üblicherweise Port 587. Implizites TLS auf Port 465 wird nicht
unterstützt. Die bestehenden Egress-Sperren für private und spezielle Zielnetze
bleiben wirksam. Ein leeres Passwortfeld behält das vorhandene Passwort desselben
Profils bei; gespeicherte Passwörter werden niemals angezeigt oder zurückgeliefert.

**Speichern und über n8n anwenden** erzeugt zunächst einen Auftrag. Mit **Status
aktualisieren** werden Fortschritt, Ergebnis und n8n-Ausführung sichtbar. Es gibt
kein automatisches Neuladen. Die Konfiguration erzeugt keine Testmail und aktiviert
keine Versandregeln. Eine angewendete Einstellung bestätigt die Übernahme der
Konfiguration, nicht die erfolgreiche Zustellung beim Provider.

## Speicherung, Isolation und Versand

`automation.smtp_configs` versioniert die zentrale Konfiguration (`owner_id IS
NULL`) und persönliche Profile (`owner_id` des angemeldeten Benutzers). Benutzer
können die Eigentümerkennung nicht als Eingabe übergeben. Versionsprüfung und
Idempotency-Key schützen vor verlorenen Änderungen und doppelten Aufträgen.
SMTP-Zugangsdaten liegen AES-256-GCM-verschlüsselt mit separater Schlüsseldatei
`smtp-keys.json` vor. Schlüssel und geschützte Laufzeitkonfiguration gehören in
die vorhandene Konfigurationssicherung.

Die API schreibt `smtp.configure` in die zentrale PostgreSQL-n8n-Queue. Die Payload
enthält nur Konfigurationskennung und Version. n8n prüft die aktuelle Berechtigung
und gibt den Auftrag frei. Der vorhandene Host-Control-Agent übernimmt freigegebene
Aufträge, erstellt eine gemeinsame Projektion aller angewendeten Profile und meldet
das Ergebnis zurück. Bei Fehlern bleibt die vorherige Projektion erhalten.

Die Notification-Komponente prüft beim Versand erneut Benutzerstatus,
Finding-Berechtigungen, Versandregel und erlaubte Empfängerdomains. Sie liest nur
die Empfänger und Routing-Metadaten, niemals SMTP-Passwörter. Alle persönlichen
Empfänger werden innerhalb derselben SMTP-Transaktion adressiert. Wird bereits
bei RCPT eine Adresse abgelehnt, wird kein DATA übermittelt.

Jedes persönliche Profil besitzt eine eigene interne Absenderkennung. Native
Postfix-Maps wählen direkt den konfigurierten SMTP-Hostname, Port und die eigenen
SASL-Zugangsdaten; `smtp_generic_maps` setzt beim Provider
den tatsächlichen Absender ein. Dadurch bleiben auch Profile mit identischer
sichtbarer Absenderadresse getrennt. Unbekannte oder entfernte Routen erhalten
keinen zentralen Fallback. Die Transportgrenzen sind weiterhin durch mTLS sowie feste Absender- und
Empfängerregeln geschützt; kein zusätzlicher Container wird benötigt.

## Konfigurationsreloads

Postfix lädt native Maps mit `postfix reload`. Es verbindet sich direkt mit den
gespeicherten Zielservern, ohne Egress-Proxy. TLS-Policy-Einträge werden je Host und
Port zusammengefasst; Zugangsdaten bleiben je Absenderkennung getrennt. Dateien
werden bei Fehlern zurückgesetzt, die Mailqueue bleibt bestehen. Container werden
für SMTP-Änderungen niemals neu gestartet. Vendor-Images bleiben unverändert.
[Details zum direkten Netzwerkbetrieb](../deployment/direct-outbound.md).
