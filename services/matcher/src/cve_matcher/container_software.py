"""Snapshot-bound container components, with separate distribution and filesystem scopes."""

import hashlib
import json
from typing import Any

MANAGERS = {
    "deb": "dpkg",
    "rpm": "rpm",
    "apk": "apk",
    "python": "pip",
    "npm": "npm",
    "java-archive": "maven",
    "go-module": "go",
    "rust-crate": "cargo",
    "gem": "gem",
    "php-composer": "composer",
    "dotnet": "nuget",
}
ECOSYSTEMS = {
    "python": "PyPI",
    "npm": "npm",
    "java-archive": "Maven",
    "go-module": "Go",
    "rust-crate": "crates.io",
    "gem": "RubyGems",
    "php-composer": "Packagist",
    "dotnet": "NuGet",
}


def software_components(
    containers: list[dict[str, Any]], bills: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    result = []
    for container in containers:
        if container["state"] != "running":
            continue
        entries = [
            e
            for e in bills
            if e["container_id"] == container["container_id"]
            and e["image_id"] == container.get("image_id")
        ]
        # A complete runtime filesystem replaces the image, including removed packages.
        runtime = [e for e in entries if e["scope"] == "runtime" and e["status"] == "complete"]
        base = runtime[-1:] or [e for e in entries if e["scope"] == "image"]
        if not runtime:
            base += [e for e in entries if e["scope"] == "runtime" and e["status"] == "partial"]
        mounts = [e for e in entries if e["scope"] == "mount"]
        for entry in base + mounts:
            document = entry.get("document")
            if not document or entry["status"] not in {"complete", "partial"}:
                continue
            os = document["os"]
            for package in document["packages"]:
                locations = package.get("locations", [])
                if (
                    entry["scope"] != "mount"
                    and locations
                    and all(
                        any(
                            path == m.get("target") or path.startswith(str(m.get("target")) + "/")
                            for m in mounts
                        )
                        for path in locations
                    )
                ):
                    continue
                kind = package["type"]
                manager = MANAGERS.get(kind, kind)
                fingerprint = hashlib.sha256(
                    json.dumps(
                        [
                            package["name"],
                            package["version"],
                            package.get("purl"),
                            entry["scope"],
                            entry.get("target"),
                        ],
                        sort_keys=True,
                    ).encode()
                ).hexdigest()
                result.append(
                    {
                        "id": "container:" + container["container_id"] + ":" + fingerprint,
                        "kind": "package",
                        "context": "container:" + container["container_id"],
                        "container_name": container.get("name"),
                        "image_id": entry["image_id"],
                        "origin": entry["scope"],
                        "target": entry.get("target"),
                        "name": package["name"],
                        "version": package["version"],
                        "comparison_version": package["version"],
                        "package_manager": manager,
                        "source_package": package.get("source_package"),
                        "source_version": package.get("source_version"),
                        "purl": package.get("purl"),
                        "distribution": os.get("id"),
                        "release": os.get("version"),
                        "ecosystem": ECOSYSTEMS.get(kind)
                        or (
                            {"debian": "Debian", "ubuntu": "Ubuntu"}.get(os.get("id", ""))
                            if manager == "dpkg"
                            else None
                        ),
                        "adapter": {
                            "dpkg": "debian",
                            "rpm": "rpm",
                            "npm": "semver",
                            "pip": "pep440",
                        }.get(manager),
                        "locations": locations,
                    }
                )
    return result
