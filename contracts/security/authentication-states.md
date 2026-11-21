# Authentifizierungszustände v1 / API 0.8.0

Konten: pending_activation, active, locked, disabled, archived. Nur active darf sich
regulär anmelden. Automatische Versuchsbegrenzung ändert diesen Zustand nicht.

unauthenticated → nach Passwort authenticated (ohne freiwillig aktivierte MFA) oder mfa_pending.
MFA-Einrichtung beginnt ausschließlich in Kontosicherheit und lässt die Sitzung authenticated.
Der Legacyzustand mfa_setup_required wird nicht mehr beim Login erzeugt.
mfa_pending → authenticated nur nach unverbrauchtem TOTP; Recovery-Code → mfa_recovery.
mfa_setup_required/mfa_recovery → authenticated erst nach bestätigtem gebundenem Enrollment.
authenticated → nach frischer Passwort-/MFA-Prüfung neue authenticated-Session mit kurzem
sessiongebundenem Reauth-Nachweis; Faktorenwechsel erzeugt eingeschränkten Setupkontext.
Alle Erhöhungen rotieren die Identität; revoked/expired sind abgeleitete Ablehnungszustände.
password_verified/reauthentication_required sind reservierte interne Zustände ohne Fachrechte.

Nur authenticated besteht authenticated_user. Alte, abgelaufene, widerrufene, fremde oder
versionsinkonsistente Sessions werden 401; unvollständige Authentifizierung wird 403.
Recovery/Sitzungsverlust darf nie automatisch MFA deaktivieren.
