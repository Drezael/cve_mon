# Kontowiederherstellung

Mit Passwort anmelden, mfa_pending erhalten, verfügbaren Recovery-Code über den
CSRF-/Origin-geschützten Endpunkt verbrauchen. mfa_recovery besitzt keine Fachrechte.
Neuen TOTP-Faktor einrichten und bestätigen; neue Recovery-Codes einmal sicher ablegen.
Andere Sessions und der alte Faktor sind widerrufen. Ein neuer Passwort-only-Login
bleibt eingeschränkt; er kann eine fremde Recovery-Session nicht übernehmen.

Bei Verlust dieser kurzlebigen Session kann ein weiterer noch gültiger Recovery-Code
nach erneuter Passwortprüfung verwendet werden. Bei Verlust aller Faktoren/Codes keine
unsichere Standardumgehung oder erneutes Bootstrap. Eigentümeridentität unabhängig prüfen,
verantworteten Operator-/Backupplan erstellen und auditieren; vollständige reguläre
Benutzer-/Faktorverwaltung folgt in Phase 9. Schlüsselverlust zunächst aus gesicherter
versionierter Keydatei wiederherstellen, keine Blanko-MFA-Deaktivierung.

Passwortreset ist ausschließlich als interne technische Grundlage implementiert.
Keine öffentliche Zustellfunktion oder Test-E-Mail versprochen. Ein künftiger
unabhängiger Kanal in Phase 19 darf ResetTokens aufrufen; ein Reset widerruft Sessions,
behält MFA und verleiht keine volle Administratoridentität.
