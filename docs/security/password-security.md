# Passwortsicherheit

argon2-cffi 25.1.0, Argon2id v19: 19456 KiB, t=2, p=1; individuelle 16-Byte-Salts und
32-Byte-Hash. Konfigurierbare sichere Grenzen: Speicher 19456–65536 KiB, Iterationen 2–4,
Parallelität 1–2 und höchstens zwei gleichzeitige KDFs (maximal 128 MiB KDF-Speicher).
Semaphore mit 250 ms Wartebudget, Ausführung im begrenzten Thread-Kontext. Cancellation
wartet auf die laufende KDF, bevor ein Slot freigegeben wird. Keine Eventloop-Blockierung.

15–256 Unicode-Zeichen nach NFC; mindestens 128 Zeichen unterstützt. Kein Trimming,
Abschneiden, Zeichenklassenmix oder periodische Zwangsrotation. Wiederholungen eines
Einzelzeichens und bekannte häufige Passwörter werden lokal abgelehnt. Die mitgelieferte
Blocklist enthält SHA-256-Digests aus der lokalen SecLists-Blocklist plus projektbezogenen Beispielen
(insgesamt 10.007 Einträge), keine passwortabhängigen Netzwerkaufrufe. Kein Anspruch auf eine vollständige
Liste aller kompromittierten Passwörter. [Provenienz](../../services/api/src/cve_api/auth/blocklist-source.json).

Auch unbekannte Konten erhalten eine echte Dummy-Argon2id-Prüfung. Fehlertexte sind für
unbekannte/falsche/inaktive Konten gleich. Beschädigte oder übermäßig teure Hashparameter
führen zu begrenzter Dummyprüfung und Ablehnung. Erfolgreiche Verifikation veralteter
Parameter erlaubt kontrolliertes Rehashing. Neue Passwörter erhöhen Credential-/Auth-
Version und widerrufen sämtliche Sessions, erneute Anmeldung erforderlich.

[OWASP-Untergrenze](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[Argon2-API](https://argon2-cffi.readthedocs.io/en/stable/api.html),
[lokale Messung](../testing/phase-08-performance.md).
