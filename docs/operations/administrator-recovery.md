# Kontrollierte Administratorwiederherstellung

Vor kritischen Änderungen mindestens einen weiteren aktiven Admin mit bestätigter MFA
und nicht widerrufenen Credentials erhalten. Letzter Admin kann nicht durch normale
Deaktivierung/Archivierung/Rollenentzug/Credential- oder MFA-Widerruf verloren gehen.
Eine abgelehnte Änderung 409 rollt vollständig zurück und wird begrenzt auditiert.

Administrative MFA-Anfrage: anderer Admin, spezielle Permission, frischer MFA-Reauth,
Zielversion und begrenzter Grund. POST users/{id}/mfa-recovery liefert nur Request-ID,
Ablauf und manual_operator_required. Ziel-Sessions/Faktoren/alte Codes werden widerrufen;
kein freier Passwort-only-Zugang. User Admin darf diese Aktion nicht ausführen.

Hostoperator prüft Antragsteller/Identität unabhängig und verwendet ausdrücklich
`scripts/security/issue-mfa-recovery.py --user-id <uuid> --request-id <uuid> --output-file <neue-private-datei>`.
Ein einmaliger Verifikator in account_tokens, Klartext nur in privater 0600-Datei. Übergabe
über einen unabhängig autorisierten Kanal; keine E-Mail-Zusage. Ziel meldet sich mit Passwort
an, erhält mfa_pending und löst POST /api/v1/auth/mfa/recovery/redeem mit CSRF/recovery_token
ein. Erst mfa_recovery, dann neues bestätigtes TOTP und neue eigene Recovery-Codes.

Wenn kein weiterer nutzbarer Admin/kein Faktor/kein Schlüsselbackup existiert: keinen
öffentlichen Bootstrap erneut öffnen. Daten sichern, Eigentümeridentität unabhängig prüfen,
Operator-/Vieraugenplan dokumentieren und in Wartungsfenster mit Migrationsinhaberrechten
gezielt wiederherstellen, Änderungen auditieren und danach normale Invariante/Keys/Seeds
prüfen. Der Owner ist eine bewusste Offline-Vertrauensgrenze, kein Runtime-Notfallkonto.
