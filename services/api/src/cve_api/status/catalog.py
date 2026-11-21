"""Code-owned catalogue: fixed existing services, DAG and closed probe addresses."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    id: str
    name: str
    dependencies: tuple[str, ...] = ()
    critical: bool = True
    job_prefix: str | None = None
    # Due job age: operator policy, not a minimum throughput requirement.
    backlog_seconds: int = 900


SERVICES = (
    Service("postgres", "PostgreSQL"),
    Service("api", "FastAPI", ("postgres",)),
    Service("nginx", "Nginx / HTTPS", ("api",)),
    Service("postfix", "Postfix Relay"),
    Service("n8n", "n8n Laufzeit", ("postgres",)),
    Service("n8n-workflow", "Zentraler n8n-Workflow", ("n8n", "postgres")),
    Service("n8n-queue", "Zentrale n8n-Queue", ("postgres", "n8n-workflow")),
    Service("jobs", "Worker-Ausführungsqueue", ("postgres",)),
    Service("outbox", "Transactional Outbox", ("postgres",)),
    Service("intake", "Inventory Intake", ("api", "postgres")),
    Service(
        "inventory",
        "Inventory Processor",
        ("jobs", "n8n-workflow", "n8n-queue"),
        job_prefix="inventory.process",
    ),
    Service(
        "importer",
        "CVE V5 Git-Import",
        ("jobs", "n8n-workflow", "n8n-queue"),
        job_prefix="cve.import.",
        backlog_seconds=3600,
    ),
    Service(
        "enricher",
        "Optionale CVE-Aufbereitung",
        ("jobs", "n8n-workflow", "n8n-queue"),
        job_prefix="cve.enrich.",
        critical=False,
        backlog_seconds=3600,
    ),
    Service(
        "matcher", "Matching Engine", ("jobs", "n8n-workflow", "n8n-queue"), job_prefix="matching."
    ),
    Service(
        "findings",
        "Finding Worker",
        ("jobs", "outbox", "n8n-workflow", "n8n-queue"),
        job_prefix="findings.",
    ),
    Service(
        "notification",
        "Notification Worker",
        ("jobs", "outbox", "n8n-workflow", "n8n-queue", "postfix"),
        job_prefix="notifications.",
    ),
    Service("dispatcher", "Event Dispatcher", ("outbox",)),
    Service(
        "ansible",
        "Ansible SSH Executor",
        ("jobs", "n8n-workflow", "n8n-queue"),
        job_prefix="inventory.ansible",
    ),
)
CATALOG = {s.id: s for s in SERVICES}
PIPELINES = {
    "inventory": ("Inventarverarbeitung", ("intake", "inventory")),
    "control": ("Zentrale n8n-Steuerung", ("n8n", "n8n-workflow", "n8n-queue")),
    "cve": ("CVE V5 Import und Suchindex", ("importer", "matcher")),
    "matching": (
        "Sicherheitsbewertung",
        ("inventory", "importer", "matcher", "findings"),
    ),
    "notifications": (
        "Benachrichtigungen",
        ("findings", "outbox", "notification", "n8n", "postfix"),
    ),
}
HTTP_TARGETS = {
    "ansible": "http://cve-automation:8000",
    "api": "http://127.0.0.1:8000",
    "intake": "http://127.0.0.1:8000",
    "inventory": "http://cve-inventory:8002",
    "importer": "http://cve-importer:8005",
    "enricher": "http://cve-enricher:8006",
    "matcher": "http://cve-matcher:8003",
    "findings": "http://cve-findings:8004",
    "dispatcher": "http://cve-event-dispatcher:8001",
    "notification": "https://cve-notification:8000",
    "n8n": "https://cve-n8n:5678",
}


def topological() -> list[str]:
    result: list[str] = []
    visiting: set[str] = set()

    def visit(key: str) -> None:
        if key in visiting or key not in CATALOG:
            raise ValueError("Unknown dependency or dependency cycle")
        if key in result:
            return
        visiting.add(key)
        for dependency in CATALOG[key].dependencies:
            visit(dependency)
        visiting.remove(key)
        result.append(key)

    for key in CATALOG:
        visit(key)
    return result


topological()
