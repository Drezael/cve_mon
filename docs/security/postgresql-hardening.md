# PostgreSQL-Härtung Phase 23

PostgreSQL bleibt einzige fachliche Datenbank; n8n bleibt getrennt. Loginrollen besitzen nur ihre Schemas/Funktionen, Anwendungsrollen sind keine Superuser und führen keine Migration aus. SECURITY DEFINER verwendet feste Suchpfade; PUBLIC ist kein ausführbarer unkontrollierter Funktionsweg. Runtime nutzt verify-full, bounded Pools, statement_timeout und explizite Transaktionen.

Migration 00031 ergänzt ausschließlich dashboard.server_list_index mit SELECT für api_security und setzt die kompatible Schemaerwartung des Statussamplers weiter. Keine fachlichen Zeilen werden aktualisiert; alte Migrationen bleiben unverändert. Nur api_security deaktiviert JIT für gemessen kleine Requestpläne. Pool-/Statementlimits, Locks, Fencing und aktuelle Autorisierung bleiben erhalten. Datenbankrechte, Constraints, Audit, Persistenz und vollständiger Restore werden nativ geprüft.
