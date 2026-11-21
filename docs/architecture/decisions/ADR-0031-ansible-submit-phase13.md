# ADR-0031: Sicherer controllerseitiger Ansible Submit

Aktueller Stand: Die frühere externe Ansible-Anbindung ist durch die
repository-eigenen Playbooks und Werkzeuge ersetzt; siehe
[ADR-0038](ADR-0038-external-configuration.md) und
[Ansible-Anleitung](../../../integrations/ansible/README.md).
Der folgende Text dokumentiert die historische Entscheidung.

Status: accepted. Datum: 07.11.2026.

Phase 13 ergänzt das vorhandene Drezael/ansible-Projekt um server.inventory.submit.yml.
Das Playbook arbeitet ausschließlich lokal, verwendet vorhandene Host-Spezifikationen,
Vaults und den Python-Launcher. Keine zusätzliche Rolle, Collection oder Remoteverbindung.
HTTP läuft ausschließlich über ansible.builtin.uri, lokale Python-Helfer erledigen
Dateisicherheit, unveränderte Kopien, PEM-Prüfung, Antwortvalidierung und atomare Receipts.

Der Uploadvertrag aus Phase 11 und die Exportformate 1.0/1.1 bleiben unverändert. Das
Beispiel im Phase-13-Konzept nennt server_uuid; die tatsächliche API verwendet server_id.
Es wird kein Alias erfunden. 202 bestätigt ausschließlich accepted nach Commit; der Client
prüft das vollständige geschlossene Receipt-Schema, eigene UUIDs, Herkunft und Status-URL.

Eine feste private Operatorconfig bestimmt HTTPS-Origin, Trust und Verzeichnisse. Tokens
und PEM-Keypasswörter kommen serverbezogen aus der bestehenden Vaultarchitektur. Dateipfade,
Rechte, Fingerprint, EKU, Laufzeit und passende Schlüssel werden geprüft. Originalbytes
bleiben unverändert, private Transferkopien und entschlüsselte Keys liegen im vorhandenen
Launcher-tmpfs. Nur für Submit setzt der bestehende Executor ANSIBLE_LOCAL_TEMP ebenfalls
in diesen Workspace; Kryptografie und andere Launcherbefehle bleiben unverändert.

Idempotenz hängt von festem Namensraum, Server-ID und SHA-256 der Originalbytes ab, nicht
von Zeit, Token oder Zertifikatsdateiname. Bis zu drei identische Versuche, begrenztes
Backoff/Retry-After und klare permanente Fehler. Keine Redirects, Umgebungsproxy-, netrc-
oder GSSAPI-Credentials und kein TLS-Fallback. Explizite Batchauswahl wird sequenziell
bearbeitet, Hostfehler bleiben isoliert; unabhängige parallele Prozesse sind geprüft.

Lokale Receipts werden erst nach bestätigtem POST atomar ohne Überschreiben erstellt.
Der Statusendpunkt enthält keinen Payload-Hash. Ein GET ohne passenden vorhandenen lokalen
Receipt kann daher keine neue Dateibytebindung beweisen und erzeugt keinen Receipt.
Fehlende Nachweise werden ausschließlich durch erneut bestätigten identischen POST repariert.
Keine Verarbeitung, Snapshots oder Jobs aus Phase 14 werden vorgezogen.

[Übergabe](../../development/phase-13-handover.md), [Abnahme](../../development/phase-13-acceptance.md).
