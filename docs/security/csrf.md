# CSRF und Browser-Origin

Jede Mutation benötigt den exakt konfigurierten HTTPS-Origin und X-CSRF-Token. Ein
zufälliger 256-Bit-Wert ist an die anonyme Challenge oder persistente Session gebunden;
nur sein Digest wird gespeichert, Vergleich mit compare_digest. GET csrf rotiert die
Challenge, Login verbraucht sie, Sessionrotation ersetzt sie. Parallele Formulare können
daher eine neue Challenge benötigen. Fremde/fehlende/veraltete Tokens führen zu 403.

Kein CORS-Vertrauen und keine Domain-Cookies. Login-CSRF wird vor Passwortprüfung
verhindert. Nginx setzt Gateway, HTTPS-Merkmal und echte Client-IP selbst; der Browser
benötigt oder kennt das Gateway-Geheimnis nicht. Mehrdeutige Host-/Origin-/Gateway-
Header und doppelte Auth-Cookies werden abgewiesen. SameSite ergänzt diese Prüfung.
Aktives Same-Origin-XSS bleibt außerhalb des Schutzes eines CSRF-Tokens.
