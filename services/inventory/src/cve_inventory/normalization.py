"""Lossless structural normalization; no version comparison or vulnerability inference."""

import hashlib
import json
import re
from datetime import datetime
from typing import Any

NORMALIZER = "inventory-1"
PROCESSOR = "0.14.0"
DISTRIBUTIONS = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "fedora": "fedora",
    "centos": "centos",
    "redhat": "rhel",
    "red hat enterprise linux": "rhel",
    "rocky": "rocky",
    "almalinux": "almalinux",
    "alpine": "alpine",
    "opensuse": "opensuse",
    "archlinux": "arch",
    "arch linux": "arch",
}


def encoded(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def unique(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(key) for key in sorted({encoded(item) for item in items})]


def version_parts(item: dict[str, Any]) -> dict[str, Any]:
    raw = item["version"]
    manager = item["package_manager"]
    epoch: str | None = None
    upstream: str | None = None
    release: str | None = None
    status = "unknown"
    rest = raw
    if manager in {"dpkg", "rpm"}:
        valid = bool(rest) and not any(c.isspace() or ord(c) < 32 for c in rest)
        if ":" in rest:
            prefix, rest = rest.split(":", 1)
            valid = valid and prefix.isascii() and prefix.isdigit()
            epoch = prefix if valid else None
        if "-" in rest:
            upstream, release = rest.rsplit("-", 1)
            valid = valid and bool(release)
        else:
            upstream = rest
        if manager == "dpkg":
            valid = valid and bool(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", upstream or ""))
            valid = valid and (release is None or bool(re.fullmatch(r"[A-Za-z0-9+.~]+", release)))
        else:
            valid = valid and bool(re.fullmatch(r"[A-Za-z0-9._+~^]+", upstream or ""))
            valid = (
                valid and release is not None and bool(re.fullmatch(r"[A-Za-z0-9._+~^]+", release))
            )
        if "epoch" in item:
            # Omitted RPM epoch is semantically 0; preserve explicit original string.
            valid = valid and item["epoch"].isascii() and item["epoch"].isdigit()
            valid = valid and (epoch is None or item["epoch"] == epoch)
            epoch = item["epoch"]
        if "release" in item:
            valid = valid and item["release"] == release
        status = "normalized" if valid else "invalid_version"
        if not valid:
            upstream = release = None
    return {
        "epoch": epoch,
        "upstream_version": upstream,
        "release": release,
        "normalization_status": status,
    }


def image_reference(reference: str) -> dict[str, str | None]:
    """Split explicit reference components without default registry, tag or product inference."""
    if re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
        return {"reference": reference, "repository": None, "tag": None, "digest": reference}
    name, separator, digest = reference.partition("@")
    tag = None
    if name.rfind(":") > name.rfind("/"):
        name, tag = name.rsplit(":", 1)
    return {
        "reference": reference,
        "repository": name or None,
        "tag": tag,
        "digest": digest if separator else None,
    }


def normalize(value: dict[str, Any], received_at: datetime) -> dict[str, Any]:
    os_data = value["os"].get("data", {})
    distribution = os_data.get("distribution")
    os_id = DISTRIBUTIONS.get(distribution.casefold()) if distribution else None
    warnings: set[str] = set()
    if distribution and os_id is None:
        warnings.add("unknown_distribution")
    packages = []
    for item in unique(value["packages"].get("items", [])):
        parts = version_parts(item)
        if parts["normalization_status"] != "normalized":
            warnings.add("package_" + parts["normalization_status"])
        packages.append(
            {
                "name": item["name"],
                "version": item["version"],
                "architecture": item["architecture"],
                "package_manager": item["package_manager"],
                "source_package": item.get("source_package", {}).get("name"),
                "source_version": item.get("source_package", {}).get("version"),
                "software_identity": "unmapped",
                "original_data": item,
                "record_sha256": hashlib.sha256(encoded(item).encode()).digest(),
                **parts,
            }
        )
    images: dict[str, dict[str, Any]] = {}
    for item in unique(value.get("images", {}).get("items", [])):
        key = item["image_id"]
        if key not in images:
            images[key] = {**item, "original_records": [item]}
        else:
            images[key]["original_records"].append(item)
            for field in ("references", "repo_digests"):
                images[key][field] = sorted(set(images[key][field] + item[field]))
            warnings.add("image_duplicate_id")
        for digest in item["repo_digests"]:
            if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", digest):
                warnings.add("image_digest_invalid")
    for image in images.values():
        image["reference_parts"] = [
            image_reference(ref) for ref in sorted(set(image["references"] + image["repo_digests"]))
        ]
    containers = unique(value.get("containers", {}).get("items", []))
    for item in containers:
        resolved = item.get("image_id") in images
        if not resolved:
            warnings.add("container_image_unresolved")
        item["image_resolved"] = resolved
        digest = item.get("image_digest")
        if digest is not None and not re.fullmatch(
            r"sha256:[0-9a-f]{64}|.+@sha256:[0-9a-f]{64}", digest
        ):
            warnings.add("container_digest_invalid")
    sections = []
    for name in ("os", "packages", "services", "containers", "images", "docker"):
        if name in value or name in {"services", "containers"}:
            section = value.get(name, {"status": "not_collected"})
            sections.append(
                {
                    "section": name,
                    "status": (
                        {
                            "available": "complete",
                            "not_installed": "not_collected",
                            "unreachable": "failed",
                        }.get(section["status"], section["status"])
                    ),
                    "error_code": section.get("error_code"),
                }
            )
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    # Even the API's permitted 5-minute skew is historical until a new collection arrives.
    plausible = captured <= received_at
    if not plausible:
        warnings.add("future_collection")
    if (received_at - captured).total_seconds() > 30 * 86400:
        warnings.add("stale_collection")
    docker = value.get("docker", {}).get("status")
    complete = value["collection_status"] == "complete"
    if docker in {"unreachable", "failed"}:
        complete = False
    return {
        "os": os_data,
        "os_id": os_id,
        "kernel": {
            "version_raw": os_data.get("kernel"),
            "architecture": os_data.get("architecture"),
            "hardware": value.get("hardware", {}),
        },
        "packages": packages,
        "services": unique(value.get("services", {}).get("items", [])),
        "containers": containers,
        "images": list(images.values()),
        "sections": sections,
        "quality": {
            "collection_status": value["collection_status"],
            "warnings": sorted(warnings),
            "diagnostics": value.get("diagnostics", []),
            "docker_status": docker,
        },
        "container_software": value.get("container_software", {}).get("items", []),
        "eligible": complete and plausible,
    }
