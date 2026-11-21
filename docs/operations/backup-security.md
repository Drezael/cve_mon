# Backupsicherheit Phase 23

Bestehende pg_dump/Globals-/Fingerprint-/Manifest-Sicherung bleibt maßgeblich. Dumpverzeichnisse0700, Dateien0600. Vor externem Transport jeden Dump und Metadatendatei mit dem neuen authentifizierten Dateiumschlag versiegeln:

`.venv/bin/python -m scripts.hardening.manage seal --source DATEI --target NEUE_DATEI --key-file SEPARATER_SCHLUESSEL`

Der Schlüssel enthält32 zufällige Bytes in Base64, private reguläre Datei0400/0600. Er wird außerhalb der Backups verwahrt; keine Schlüsselwerte in Arguments, Logs oder Repository. Bereits vorhandene Schlüssel werden nicht überschrieben. decrypt über unseal verlangt neues Ziel; bei Manipulation, abgeschnittener Endmarke, falschem Schlüssel oder unerwarteten Daten wird kein fertiger Klartext veröffentlicht.

AES-256-GCM verarbeitet64KiB-Records. Pro Datei erzeugt ein zufälliger256-Bit-Salt über HKDF-SHA256 einen separaten Dateischlüssel; der96-Bit-Nonce enthält einen monotonen Zähler. Header, Reihenfolge und Endmarker werden authentifiziert. Format2 wird geschrieben; der initiale lokale Format1-Bestand bleibt lesbar. Maximale Größe64GiB, kein unbeschränkter Speicherread und keine Archivextraktion. Klartextquellen werden nicht still gelöscht. Für Offsite-Archivierung müssen sie auf geschütztem temporärem Speicher kontrolliert entfernt werden; das Tool ersetzt keine Datenträger-/Retentionpolitik. TLS-/MFA-/n8n-Schlüssel und persistente Mailqueue sind separat mit vorhandenen jeweiligen Sicherungswegen einzubeziehen.
