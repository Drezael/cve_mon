"""Cross-record invariants shared by inventory admission and asynchronous processing."""

from datetime import datetime, timedelta
from typing import Any


def validate_links(value: dict[str, Any]) -> None:
    containers = {
        c["container_id"]: c.get("image_id") for c in value.get("containers", {}).get("items", [])
    }
    seen = set()
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    for entry in value.get("container_software", {}).get("items", []):
        key = (entry["container_id"], entry["scope"], entry.get("target"))
        if key in seen or containers.get(entry["container_id"]) != entry["image_id"]:
            raise ValueError("container_software_binding")
        seen.add(key)
        observed = datetime.fromisoformat(entry["captured_at"].replace("Z", "+00:00"))
        if observed > captured + timedelta(minutes=5):
            raise ValueError("container_software_timestamp")
