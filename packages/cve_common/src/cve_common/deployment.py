"""Shared physical deployment and logical service endpoint contract."""

APPLICATION_IMAGE = "cve-application:0.24.0"
GROUPS = {
    "cve-api": ("cve-api",),
    "cve-processing": (
        "cve-event-dispatcher",
        "cve-inventory",
        "cve-matcher",
        "cve-findings",
        "cve-notification",
        "cve-importer",
        "cve-enricher",
    ),
    "cve-sources": ("cve-automation",),
}
PORTS = {
    "cve-api": 8000,
    "cve-event-dispatcher": 8001,
    "cve-inventory": 8002,
    "cve-matcher": 8003,
    "cve-findings": 8004,
    "cve-notification": 8000,
    "cve-importer": 8005,
    "cve-enricher": 8006,
    "cve-automation": 8000,
}
VENDORS = ("cve-nginx", "cve-postgres", "cve-mail-relay", "cve-n8n")
SERVICES = (*GROUPS, *VENDORS)
OPTIONAL_SERVICES = ("cve-mailhog", "cve-certbot")

# Status IDs resolve only to code-owned logical processes, never arbitrary Docker targets.
RESTART_TARGETS = {
    "api": "cve-api",
    "inventory": "cve-inventory",
    "importer": "cve-importer",
    "enricher": "cve-enricher",
    "matcher": "cve-matcher",
    "findings": "cve-findings",
    "notification": "cve-notification",
    "dispatcher": "cve-event-dispatcher",
    "ansible": "cve-automation",
}
