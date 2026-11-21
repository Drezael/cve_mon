# Abhängigkeiten

PostgreSQL ist Voraussetzung der API und Jobs/Outbox; Nginx hängt fachlich von der API ab. Importer und Enricher verwenden Jobs und Envoy; Postfix verwendet Envoy; Notification hängt von Jobs, Outbox, n8n und Postfix ab. Abhängigkeiten sind Hinweise, keine bewiesene Ursache. Abhängige Ausfälle werden korreliert, Pipelinealarme und periodische Duplikate werden nicht veröffentlicht. Status lesende Endpunkte werten Freshness erneut aus.
