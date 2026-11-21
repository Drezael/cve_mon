"""Physical deployment groups and stable logical application identities."""

from cve_common.deployment import APPLICATION_IMAGE, GROUPS, PORTS, SERVICES, VENDORS

__all__ = ["APPLICATION_IMAGE", "GROUPS", "PORTS", "SERVICES", "VENDORS", "physical", "arguments"]


def physical(service: str) -> str:
    return next((group for group, roles in GROUPS.items() if service in roles), service)


def arguments(values: list[str]) -> list[str]:
    """Map service selectors, never executable arguments or inline scripts."""
    if not values or values[0] not in {
        "up",
        "stop",
        "start",
        "restart",
        "ps",
        "logs",
        "create",
        "rm",
        "kill",
        "exec",
        "run",
    }:
        return values
    result: list[str] = []
    seen: set[str] = set()
    command = values[0]
    for i, value in enumerate(values):
        mapped = physical(value)
        if value in PORTS or value in GROUPS:
            if mapped not in seen:
                result.append(mapped)
                seen.add(mapped)
            if command in {"exec", "run"}:
                return result + values[i + 1 :]
        else:
            result.append(value)
    return result
