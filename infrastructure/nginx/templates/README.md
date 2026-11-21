# Templateverarbeitung

scripts/infrastructure/manage.py ersetzt nur explizit freigegebene ${GROSSBUCHSTABEN}-Variablen
nach strenger Konfigurationsprüfung. Nginx-eigene $host/$uri/$request_id bleiben erhalten.
Keine Shell-/eval-Auswertung. Keine Zertifikats-Private-Keys in Templates.
Die Domain-/Port-/Limitparameter kommen aus validierter Umgebung; Runtime-Pfade im Container
sind fest. Der technische Uploadproxy ist noch nicht aktiviert.
