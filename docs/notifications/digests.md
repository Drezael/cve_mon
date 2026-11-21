# Digest und Ruhezeiten

Unterstützte Intervalle: 1, 24 und 168 Stunden. Fenster sind feste, halboffene UTC-Intervalle
nach Verarbeitungszeit; dadurch überschneiden sie sich nicht und hängen nicht von lokalen
Uhrzeitfaltungen ab. Die Benutzerzeitzone dient Darstellung und Ruhezeit. Jeder Digest ist
empfängerbezogen und referenziert seine einzelnen, persistenten Event-Intents.

Nach Ausfällen bleiben überfällige Digest-Eltern erhalten; n8n-Zeitpläne und der persistente
Maintenance-Job holen sie nach. Vor Submit werden alle enthaltenen Finding-Referenzen in
einer Sammelabfrage erneut auf aktuelle Rechte und Regelgültigkeit geprüft. Unzulässige
Mitglieder werden begründet unterdrückt. Ein leerer Digest erzeugt keine SMTP-Übergabe.
Die Sortierung erfolgt nach Priorität. Eltern besitzen einen eigenen stabilen Message-ID-
und Zustellversuchsverlauf; Mitglieder bleiben als Referenzen auf diesen Digest erhalten.

Ruhezeiten bestehen aus IANA-Zone, Wochentagen und lokalen Anfangs-/Endzeiten. Die Suche
läuft über tatsächliche UTC-Minuten und behandelt daher beide Sommerzeitfaltungen und
fehlende lokale Uhrzeiten eindeutig. Ein nächster Versandzeitpunkt wird begrenzt ermittelt;
max_deferral_hours verhindert unendlichen Aufschub. Pflicht-/kritische Ausnahmen sind Policy.
