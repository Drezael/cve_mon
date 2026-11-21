# Authentifizierung und Sitzungen Phase 23

Die vorhandene Phase-8-Implementierung bleibt maßgeblich. Passwortverifikatoren und MFA-Schlüssel liegen nicht im Browser; Authcookies sind Secure/HttpOnly/SameSite mit Hostbindung. Sessionrotation, absolute/idle Ablaufzeit, MFA-Zustand, Credential-/Authversion und Widerruf werden serverseitig geprüft. Rechte werden pro Serviceoperation unter den vorhandenen geordneten Sicherheitslocks neu geladen.

Zusätzlich werden mehrere Cookieheader ausdrücklich abgewiesen. Kleine authentifizierte JSON-Requests weisen doppelte Schlüssel, nichtendliche Zahlen, ungültiges UTF-8, unpaarige Surrogate/NUL und mehr als 32 Ebenen vor Modell-/DB-Verarbeitung zurück. Transportprüfung geht dem Parser voraus; der getrennte 10-MiB-Inventarparser bleibt unverändert. Keine Lockerung von Passwort-/MFA-/CSRF-/Rate-Limits zur Leistungssteigerung. Authentifizierungsregression: phase-23-auth.xml; HTTP-Negativfälle: phase-23-api.xml.
