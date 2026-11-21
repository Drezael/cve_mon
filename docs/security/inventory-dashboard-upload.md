# Dashboard-Dateiannahme

Seit Schema 1.2 und Migration `00041_server_discovery` gilt der vereinfachte
[Onboarding-Ablauf](../operations/server-onboarding.md): Upload ohne Vorabregistrierung,
automatische Serveranlage und wiederverwendbare Collector-Zugänge. Die folgenden
Abschnitte beschreiben den erhaltenen ursprünglichen Uploadvertrag.


Cookieidentität aus Phase 8 und frische SQL-Rollen/ACLs aus Phase 9. MFA gemäß Konto-/Rollen-
richtlinie, CSRF und exakte Origin. Nur inventory:upload:dashboard + explizites Serverupload-
ACL erlaubt Annahme, kein server:read/group:read, keine Gruppenvererbung und kein Adminbypass.
Teilweise MFA-Sessions, Maschinenbearer und fremde Zielserver werden abgewiesen.

Genau server_id und eine application/json-Datei mit begrenztem .json-Basisnamen. Der Name
wird nie als Speicherpfad genutzt oder dauerhaft gespeichert. Tatsächliche Bytes, Multipart-
Teile und Datei werden unabhängig von Content-Length gezählt. Begrenzt gespeicherte Spooldatei
bleibt innerhalb des Datei-RAM-Limits; Übergröße wird vor Überschreiten abgebrochen, Dateien
auch bei Fehlern geschlossen. Zusätzliche Dateien/Felder, Kompression und andere Formate
werden zurückgewiesen. Serverseitige Datei-ID muss zur autorisierten Ziel-ID passen.

Status nur mit inventory:read, aktuellem view-ACL und eigener Benutzeridentität. Keine
fremden oder technisch eingelieferten Receipts. Status enthält keinen Payload. GUI folgt
Phase 20–21, sämtliche Grenzen bleiben Backendentscheidungen.
