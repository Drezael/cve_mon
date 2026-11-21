# Sessions v1

__Host-cve-session und __Host-cve-login: opaque UUID + 256-Bit-Verifikator,
Secure/HttpOnly/SameSite=Strict/Path=/ ohne Domain. Der Datenbankwert ist ein Digest.
CSRF-Verifikation getrennt vom Session-Verifikator. Cookie nie in allgemeinen Antworten.

GET csrf gibt den CSRF-Wert aus; Login mit anonymem Cookie benötigt nach einem Fehlversuch
neue Vorbereitung. Mutationen: Origin + X-CSRF-Token. Sessionrotation gibt einen neuen
CSRF-Wert und Cookie aus. Exakter Origin aus Deploymentkonfiguration. Maximal 8 KiB Body.
[Konkrete API](../api/authentication.openapi.yaml), [Zeiten und Widerruf](../../docs/security/sessions.md).
