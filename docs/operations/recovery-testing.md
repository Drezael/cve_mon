# Recoverytests Phase 23

Eigene Laborprojekte prüfen PostgreSQL-Neustart/-Restore, Workerabsturz vor/nach Commit, verlorene Lease, verspätete Ergebnisse, Outbox-Wiederaufnahme und Dienststörungen. Die Statuslaufzeit prüft n8n/Envoy/Postfix/API/PG mit tatsächlichen Containern; Nginx-Neustart und anhaltende Queuezustände werden durch vorhandene Infrastrukturtests geprüft. Ein unabhängiger externer Beobachter wird nicht erfunden.

Volles Dateisystem/Datenbank werden durch einen tatsächlich erschöpften begrenzten Tablespace im eigenen PostgreSQL-tmpfs geprüft, nicht durch Füllen der Hostdisk. Wiederanlauf darf alte Arbeit nicht als aktuellen Erfolg publizieren. Alle Fach-/Audit-/Deduplikationsinvarianten werden erneut geprüft. make resilience-test und make recovery-test; keine produktiven Störungssimulationen.
