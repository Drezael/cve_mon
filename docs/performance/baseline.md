# Performancebaseline Phase 23

Vor der Performanceänderung wurden alle drei Laststufen tatsächlich gemessen. Das Testprogramm und seine Umgebungsgrenzen stehen in tests/hardening/test_workload.py und workload-model.md. Die Rohproben bleiben erhalten. Teilweise gescheiterte Entwicklungsversuche sind in privaten Berichten nachvollziehbar; sie wurden nicht als Abnahme verwendet.

Erster Befund: PostgreSQL-JIT kompiliert 135 Funktionen, rund1,18s allein für Kompilation eines kleinen Listenzugriffs. Dieselbe Sitzung plus langsame Detailprojektion erschöpft den kleinen Pool. API-p95 rund4,1–4,2s, Fehler auf allen Stufen, bei10000 Servern24/24. Kein Erhöhen der Pools/Timeouts und kein Weglassen der Authentifizierung.

Weitere Messungen und Vorher-/Nachherwerte werden im Ergebnisbericht aus den tatsächlichen JSON-Daten erzeugt. CPU-/RAM-/I/O-Werte sind host-/containerabhängig. Dieselben Paket- und Ergebnisinvarianten gelten in beiden Durchläufen.
