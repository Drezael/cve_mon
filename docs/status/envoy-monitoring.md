# Envoy-Beobachtung

Ein fester lokaler Bash-Adapter verwendet nur den vorhandenen Loopback-Healthcheck und einen eng begrenzten Statsfilter für upstream_cx_connect_fail. Keine Weiterleitung der Admin-API und kein zusätzlicher Port. Nur ein aggregierter Zähler gelangt zum Collector. Readiness beweist nicht die Erreichbarkeit aller externen Quellen: EGRESS_ACTIVITY_NOT_VERIFIED bleibt dafür ausdrücklich unknown. Healthchecks starten keinen Import und keinen externen Egress-Test; Allowlist und Routing werden nicht erweitert.
