# Zertifikatsrotation

## Öffentliches Dashboard-Zertifikat

Bei aktiviertem Certbot übernimmt der Cloudflare-DNS-01-Dienst die Erneuerung.
Der Hostcontroller prüft die Quelldateien alle 60 Sekunden und lädt Nginx nach
Prüfung von Domain, Kette und Schlüsselpaar neu. Ein ungültiges Paar ersetzt den
aktiven Stand nicht. Kein manueller Austausch von Zertifikatspfaden pro Dienst.

[Einrichtung, Dry-run und Fehlerhilfe](../deployment/letsencrypt-cloudflare.md).

Bei extern gepflegten Zertifikaten das vollständige erneuerte Paar unter
`TLS_DIR` bereitstellen. `fullchain.pem` und `privkey.pem` müssen zusammenpassen.
Certbot-Symlinks nach `archive/` bleiben unterstützt. Vor der Umstellung eine
Sicherung erstellen und nach der automatischen Übernahme Name, Kette, Laufzeit
und den tatsächlichen Dashboard-Zugang prüfen.

Ein Wechsel des Cloudflare-API-Tokens erfolgt über die private Instanzkonfiguration
und einen regulären `cve_mon start`. Er erzeugt nicht automatisch einen neuen
Zertifikatsschlüssel. Vor dem Widerruf des alten Tokens die neue DNS-Berechtigung
mit einem Dry-run prüfen.

## Interne Identitäten und Vertrauenswechsel

Interne Dienstzertifikate und Client-CAs sind vom öffentlichen Dashboard-Zertifikat
getrennt. Ein CA-Wechsel benötigt eine geplante Übergangsphase und die Prüfung
aller betroffenen internen TLS-Verbindungen; Zertifikatsprüfung nicht abschalten.
Zertifikatsgebundene technische Uploadidentitäten brauchen entsprechend gebundene
Nachfolger. Bei kompromittierten Identitäten außerdem die vorgesehenen
Widerrufs-/Registrierungsverfahren anwenden.

Private Schlüssel, ACME-Konto und DNS-Zugangsdaten geschützt außerhalb der Images
und des versionierten Repositorybestands sichern.
