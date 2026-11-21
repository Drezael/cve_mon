# Wartungsfenster

Nur deployment:maintenance:manage mit vollständiger MFA, CSRF und frischem Step-up erlaubt Erstellen, Bearbeiten und Absagen. Zeitpunkte sind timezone-aware, Ende liegt nach Beginn, maximal 90 Tage; Dienstliste ist eindeutig und stammt aus dem festen Katalog. PUT/DELETE benötigen starke If-Match-Versionen; fehlende Version 428, veraltet 412. Jede Mutation erzeugt einen append-only Eintrag in status.audit. Absagen löscht keine Historie. Wartung startet oder stoppt nichts, überschreibt keinen Rohzustand und unterdrückt keine Alarme.

Geplante Wartung wird bei Verfügbarkeitsberechnungen nicht abgezogen; sie bleibt getrennte Metadaten. Auditdatensätze enthalten die vorherigen und neuen Werte sowie Actor, Grund und Objektversion.

Die vorhandene minimierte Phase-21-Auditansicht enthält auch Status-Wartungsaktionen. Vorherige und neue Werte verbleiben geschützt im Status-Audit; die allgemeine Liste zeigt keine Rohdaten.
