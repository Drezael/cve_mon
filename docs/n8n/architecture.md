# n8n-Betriebsmodell

Offizielles n8n 2.44.7 ist per Multiarch-Digest in compose.yml gepinnt. EXECUTIONS_MODE=regular,
DB_TYPE=postgresdb, Datenbank n8n und Login n8n_app. Keine Redis-/Queue-Mode-Abhängigkeit.
Die vorher vorhandene leere n8n-Datenbank wird ausschließlich durch n8n selbst migriert;
Alembic verwaltet nur cve_monitoring. Encryption Key und .n8n-Daten bleiben persistent.

Der Container läuft ohne Root/Capabilities/Hostports/Socket, mit Read-only-Dateisystem,
begrenztem Scratch-Cache und privaten Secret-Mounts. Direkter Egress und allgemeine
Kommunikation zu anderen internen Diensten werden durch den Namespace-Guard gesperrt.
Nur eigene PostgreSQL- und Notification-Verbindungen, DNS und lokale Gesundheit sind erlaubt.
Die Editoroberfläche ist deaktiviert; es gibt keine öffentliche n8n-Route;
Workflows werden durch autorisierte Hostoperatoren mit den versionierten CLI-Tools verwaltet.
