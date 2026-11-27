# Automatische Servererfassung

Die Serververwaltung bietet eine optionale SSH-Verbindung pro Server. Nach dem
Anlegen richtet der Benutzer zunächst unter **Einstellungen → Mein Ansible-Vault**
sein persönliches Vault-Passwort ein. Erst danach können Host/IP, Port, Benutzer
und Schlüssel oder Passwort hinterlegt werden.
Eine Schlüssel-Passphrase ist optional; sudo und Root-Anmeldung sind ausgeschlossen. Geheimnisse
werden nicht zurückgegeben; leere Eingaben behalten gespeicherte Werte bei.

## Persönlicher Vault

Jeder Benutzer besitzt einen eigenen zufälligen 256-Bit-Vault-Schlüssel. Ein aus
dem Vault-Passwort mit Argon2id abgeleiteter Schlüssel schützt diesen Schlüssel;
das Passwort selbst wird nicht gespeichert. Das Passwort muss 15 bis 256 Zeichen
enthalten und zur Bestätigung zweimal eingegeben werden. Einrichtung und Änderung
erfordern die bestehende erneute Kontoanmeldung, einschließlich MFA, falls aktiviert.
Für einen Passwortwechsel ist zusätzlich das bisherige Vault-Passwort notwendig.
Dabei bleiben bereits hinterlegte SSH-Zugangsdaten und Zeitpläne verwendbar.
Vergessene Vault-Passwörter können weder angezeigt noch heruntergeladen werden.

SSH-Passwörter, private Schlüssel und Schlüssel-Passphrases werden einzeln mit
AES-256-GCM verschlüsselt und an Benutzer, Server und Feld gebunden. Nur der
Profileigentümer darf diese Zugangsdaten ersetzen; auch Administratoren erhalten
keinen Lese- oder Downloadzugriff. Die API liefert ausschließlich Verbindungsdaten,
Konfigurationsstatus und Laufmetadaten. Profiländerungen übernehmen unveränderte
Geheimnisfelder verschlüsselt, ohne sie zu entschlüsseln. Ein neuer privater
Schlüssel ohne neue Passphrase entfernt die bisherige Passphrase.

Damit geplante Abfragen ohne erneute Eingabe möglich bleiben, wird der persönliche
Vault-Schlüssel zusätzlich mit dem separaten SSH-Dienstschlüssel verschlüsselt.
Der Executor entschlüsselt die benötigten Zugangsdaten erst während eines Laufs
und übergibt sie über eine private Prozess-Pipe an den festen Ansible-Runner.
Hostkey-Abfragen benötigen keine Entschlüsselung der SSH-Zugangsdaten.
Es gibt keine Klartext-`plan.json`, keine Übergabe als Kommandozeilenargument und
keine Übergabe der Geheimnisse an n8n oder die Jobqueue. Von Ansible benötigte
temporäre Schlüssel-/Inventardateien liegen ausschließlich im privaten
tmpfs-Arbeitsverzeichnis; dieses wird nach Erfolg, Fehler oder Abbruch entfernt.
Core-Dumps sind für Executor und Runner deaktiviert.
Private Schlüssel und Passphrases werden vor `ssh-add` lokal geprüft; falsche
Passphrases beenden den Lauf mit `ssh_credentials_invalid`, statt wiederholt
Passworteingaben anzufordern. Für passphrasegeschützte OpenSSH-Schlüssel ist die
optionale `bcrypt`-Unterstützung von `cryptography` in den gesperrten
Laufzeitabhängigkeiten enthalten; siehe [Schlüsselimport](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).

Diese Absicherung verhindert das Auslesen über die Anwendung. Ein Administrator
mit Kontrolle über Host, Dienstschlüssel und laufende Prozesse kann technisch auf
Laufzeitgeheimnisse zugreifen. Auch unverschlüsselter Swap und Host-Speicherabbilder
liegen außerhalb dieser Anwendungsgrenze. Datenbank-Backups und die getrennten
Dienstschlüssel müssen deshalb weiterhin geschützt werden. Der Vault betrifft die
verwaltete Ansible-Anbindung; persönliche SMTP-Einstellungen verwenden weiterhin
ihre eigene Verschlüsselung.

Mit Migration `00075_personal_ansible_vault` werden bisherige Ansible-Profile
deaktiviert und ihre alten Läufe durch eine neue Profilversion ungültig. Bisherige
verschlüsselte Zugangsdaten bleiben bis zur expliziten Neukonfiguration erhalten,
werden aber nicht mehr ausgeführt oder automatisch übernommen. Jeder Eigentümer
richtet seinen Vault ein, hinterlegt die Zugangsdaten pro Server erneut und aktiviert
anschließend gegebenenfalls den Zeitplan. Beim Speichern ersetzen die neuen
Vault-Credentials die alten verschlüsselten Daten.

Vor dem ersten Login wird der öffentliche SSH-Hostkey ohne Anmeldung ausgelesen.
Der Benutzer vergleicht ihn mit dem Zielsystem und bestätigt ihn ausdrücklich.
Anschließend sind Verbindungstest, manuelle Erfassung und regelmäßige Erfassung
möglich. Änderungen an Host oder Port erfordern eine neue Bestätigung. Ein
abweichender Hostkey verhindert den Login.

Das Intervall beträgt mindestens fünf Minuten und höchstens sieben Tage. Nur der
bestehende n8n-Inventarworkflow plant fällige Läufe und gibt manuelle Aufträge
frei. Ein angehaltener Workflow verhindert die Ausführung. PostgreSQL enthält
Verbindungsprofil, verschlüsseltes Credential, geplante Läufe, Status, Fehlercode,
n8n-Ausführungsbezug und die zugehörige Inventarübernahme. Auch Hostkey-Abfragen
und Verbindungstests durchlaufen diese Steuerung.

## Ausführung und Netz

Es bleiben drei eigene Container: API, Verarbeitung mit Import/Enrichment und
SSH-Ausführung im bisherigen Dienst `cve-sources`. Herstellerimages bleiben
unverändert. Der Executor läuft ohne Root, zusätzliche Capabilities oder Zugriff
auf den Docker-Socket. Er startet ausschließlich das mitgelieferte Playbook.
Arbeitsdateien liegen pro Lauf privat in einem tmpfs und werden entfernt.

Alle Zielnetze und Zieladressen sind zugelassen, einschließlich öffentlicher
IPv4-/IPv6-Adressen. Es gibt keine Netz-Allowlist in der `.env`. Der Hostcontroller
setzt eine Firewall im Executor-Namespace: Neben der internen PostgreSQL-Verbindung
sind nur die konkreten SSH-Adressen und Ports aktiver Verbindungsprofile freigegeben.
Namen werden vor der Verbindung aufgelöst; der bestätigte SSH-Hostkey bleibt bindend.
Die Erreichbarkeit hängt weiterhin von Routing und Host-/Ziel-Firewall ab.

## Beschränkter Benutzer und lesende Erfassung

Auf dem Zielhost einen eigenen Benutzer, beispielsweise `cve-inventory`, mit
SSH-Schlüssel und ohne sudo-Rechte verwenden. Nur benötigte System-/Paketinformationen
und explizit ausgewählte Anwendungspfade lesbar machen. Die API lehnt Root als
Benutzernamen sowie aktiviertes sudo ab; der Runner prüft zusätzlich die tatsächliche
UID und bricht bei UID 0 ab. Bestehende sudo-Profile müssen angepasst werden.

Das feste Playbook liest Linux-Fakten, Pakete, Dienste und vorhandene
Docker-Container mit Softwareinventar. Es installiert nichts und ändert weder
Systemkonfiguration noch überwachte Images oder Container. Benutzerdefinierte
Playbooks und Befehle können nicht über die API eingereicht werden. Eine bestehende
Monitoring-ID wird weiter gelesen; andernfalls wird eine stabile Identität aus
Hostinformationen abgeleitet, ohne eine neue Identitätsdatei anzulegen.

Ansible verwendet SSH-Pipelining. Für Modul-Ausführung und SBOM-Auswertung sind
private temporäre Dateien möglich; SBOM-Arbeitsdateien und Exporte werden nach
jedem Lauf entfernt. Es werden keine dauerhaften Syft-Binaries oder Caches auf
dem Ziel angelegt. Normale Betriebssystemprotokolle und Dateizugriffszeiten können
sich durch einen SSH-Lesezugriff weiterhin ändern.

Ein Administrator installiert die Voraussetzungen vorab:

- SSH-Server und Python 3; Ansible selbst läuft im Executor.
- Für Paketfakten gegebenenfalls `python3-apt` (Debian/Ubuntu) oder `python3-rpm`
  (RPM-Distributionen).
- Für Docker: vorhandene Engine und Docker-CLI sowie den unten beschriebenen
  Leseendpunkt. Keine Installation oder Veränderung von überwachten Images.
- Für die Softwareanalyse: Syft unter `/usr/local/bin/syft`, passend zur
  Hostarchitektur. Die Referenzversion und geprüften Release-Prüfsummen stehen in
  [`syft.lock.json`](../../scripts/container_inventory/syft.lock.json).
  Das Werkzeug kann administrativ mit
  `python3 -m scripts.container_inventory.install --destination /usr/local/bin/syft`
  aus einem bereitgestellten Checkout installiert werden; der Inventarlauf tut dies nicht.
- `/usr/bin/prlimit` aus den util-linux-Werkzeugen und ausreichend temporärer
  Speicher für SBOMs beziehungsweise Containerexporte (je Export höchstens 2 GiB).

## Docker ausschließlich lesend anbinden

Der Collector verwendet fest den Unix-Endpunkt
`/run/cve-monitoring/docker-readonly.sock` auf dem Zielhost. Ein Administrator
stellt ihn über einen beschränkten API-Proxy oder eine gleichwertige
Autorisierung bereit und erlaubt dem Inventarbenutzer nur diesen Zugang.
Der normale Docker-Socket darf dem Benutzer nicht zugänglich sein; weder
Docker-Gruppenmitgliedschaft noch sudo für Docker vergeben. Ein read-only
Dateisystemmount des normalen Sockets beschränkt keine Docker-API-Befehle.
[Docker-Daemonrechte](https://docs.docker.com/engine/security/) und
[Autorisierung](https://docs.docker.com/engine/extend/plugins_authorization/).

Der Proxy muss standardmäßig ablehnen und ausschließlich benötigte Leseoperationen
zulassen, einschließlich ihrer API-versionierten Pfade:

| Methode | Pfad | Verwendung |
|---|---|---|
| GET/HEAD | `/_ping` | Erreichbarkeit und API-Aushandlung |
| GET | `/version`, `/info` | Engine-/API-Informationen |
| GET | `/containers/json` | Container auflisten |
| GET | `/containers/{id}/json`, `/containers/{id}/changes` | Metadaten und Dateisystemänderungen |
| GET | `/containers/{id}/export` | Laufendes Dateisystem lesend exportieren |
| GET | `/images/json`, `/images/{id}/json` | Lokale Images auflisten/prüfen |
| GET | `/images/get`, `/images/{id}/get` | Lokale Image-Layer für Syft lesen |

POST, PUT, PATCH, DELETE und andere Operationen bleiben gesperrt; insbesondere
kein Create, Start, Stop, Exec, Pull, Build oder Remove. Den Leseendpunkt nur
lokal bereitstellen und nicht als Hostport veröffentlichen. Auch Image-Layer und
Containerexporte können vertrauliche Daten enthalten; diesen Lesezugriff nur dem
Inventarbenutzer gewähren.

Fehlt der beschränkte Socket oder ein Werkzeug, wird kein unbeschränkter Socket
und kein sudo als Ersatz verwendet. Entsprechende Inventarteile bleiben
unvollständig. Syft verwendet lokale Docker-Images und kein Registry-Pull;
Updatechecks und Java-Netzanreicherung sind für die integrierte Erfassung deaktiviert.
Mountanalysen sind auf explizit konfigurierte Anwendungspfade mit vorhandenen
Leserechten begrenzt. Der CVE-Abgleich erfolgt anschließend im Monitor.

## Dauerhaftes Löschen

Die Löschaktion entfernt Server, Inventare, Findings mit Historie, Zugriffsrechte,
SSH-Profil, Aktualisierungsläufe und abhängige Jobs. Laufende Executor-Prozesse
werden beendet; alte Ergebnisse können keine gelöschten Server neu anlegen.
Gemeinsam genutzte Softwaredokumente werden erst ohne verbleibende Referenzen
entfernt. Das lokale Steuerprogramm bereinigt zugehörige n8n-Ausführungen und
noch wartende E-Mails. Ein persistentes Löschjournal ermöglicht Wiederaufnahme
nach einem Abbruch; eine erfolgreiche Antwort erfolgt nach der Bereinigung.

Verwaltete lokale Sicherungen, die frühere Serverdaten enthalten könnten, werden
mit ihren Schlüsseln verworfen. Sicherung und Löschung sind gegenseitig gesperrt.
Eine anonyme Sicherungsgeneration verhindert Wiederherstellungen älterer
Sicherungen nach einer Löschung. Vom Betreiber separat kopierte externe
Sicherungen und bereits zugestellte E-Mails bleiben in dessen Verantwortung.
