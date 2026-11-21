# Invariante v1

Nach jedem normalen Commit eines bereits initialisierten Systems existiert mindestens ein
aktiver admin mit gültigen Credentials. Nur wenn dieser Benutzer MFA selbst aktiviert
hat, muss dafür auch ein bestätigter nicht widerrufener Laufzeitfaktor verfügbar sein.
Transaktionale Advisory-Serialisierung, finaler Constraint-Check; kein ungesichertes COUNT
vor einer Änderung. Erster Bootstrap ist bereits ohne MFA ein nutzbares Administratorkonto;
nach armed gibt es keinen Runtime-Schalter zurück. Native Trigger schützen auch direkte
gewöhnliche Security-SQL-Mutationen. Physische Schlüsselwiederherstellung bleibt Offlinebetrieb.
