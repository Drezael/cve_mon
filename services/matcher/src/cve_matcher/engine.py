"""Pure, deterministic identity/evidence/coverage decisions over persisted inputs."""

import contextlib
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from cve_matcher.contracts import Decision, Evaluation, Status
from cve_matcher.cpe import configuration, parts
from cve_matcher.limits import EvaluationLimit as EvaluationLimit
from cve_matcher.limits import cpe_leaves
from cve_matcher.ranges import osv
from cve_matcher.versions import VersionError, compare


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def purl_key(value: str) -> str | None:
    """Identity only: retain type/namespace and all qualifiers, omit version/subpath."""
    if not value.startswith("pkg:") or len(value) > 2048:
        return None
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        return None
    try:
        parsed = urlsplit(value[4:])
    except ValueError:
        return None
    path = parsed.path.rsplit("@", 1)[0]
    if parsed.netloc or not re.fullmatch(r"[a-z][a-z0-9.+-]*/.+", path):
        return None
    try:
        segments = [unquote(segment, errors="strict") for segment in path.split("/")]
    except UnicodeError:
        return None
    if any(not segment or any(ord(c) < 32 for c in segment) for segment in segments):
        return None
    path = "/".join(quote(segment, safe="@:+.-_") for segment in segments)
    if "/" not in path or any(c.isspace() for c in value):
        return None
    try:
        qualifiers = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None
    if len({key.lower() for key, _ in qualifiers}) != len(qualifiers):
        return None
    if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", key) or not val for key, val in qualifiers):
        return None
    query = "&".join(
        quote(key.lower(), safe="") + "=" + quote(val, safe="")
        for key, val in sorted((k.lower(), v) for k, v in qualifiers)
    )
    return path + ("?" + query if query else "")


def ecosystem_name(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def source_keys(affected: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for item in affected:
        kind, value = item.get("kind"), item.get("value", {})
        if kind == "osv_package" and isinstance(value, dict):
            package = value.get("package", {})
            if package.get("name") and package.get("ecosystem"):
                keys.add(
                    "osv:"
                    + package["ecosystem"]
                    + ":"
                    + ecosystem_name(package["ecosystem"], package["name"])
                )
                if package["ecosystem"].split(":")[0] in {"Ubuntu", "Debian"}:
                    keys.add(
                        "osv-source:" + package["ecosystem"].split(":")[0] + ":" + package["name"]
                    )
            purl = purl_key(package.get("purl", ""))
            if purl:
                keys.add("purl:" + purl)
        elif str(kind).startswith("ubuntu_"):
            for package in value if isinstance(value, list) else [value]:
                if isinstance(package, dict) and package.get("name"):
                    keys.add("source:" + package["name"])
                    # Conservative candidate search also includes unproven binary names.
                    keys.add("name:" + package["name"])
        elif kind == "cna_product" and isinstance(value, dict):
            if value.get("vendor") and value.get("product"):
                keys.add("product:" + value["vendor"].lower() + ":" + value["product"].lower())
            if value.get("product"):
                keys.add("name:" + value["product"])
        elif kind == "nvd_configuration_logic":
            for leaf in cpe_leaves(value):
                try:
                    p = parts(leaf.get("criteria", ""))
                    if all(v not in {"*", "-"} and "*" not in v and "?" not in v for v in p[:3]):
                        keys.add("cpe:" + ":".join(p[:3]).lower())
                    else:
                        keys.add("cpe-wildcard")
                except ValueError:
                    pass
    return keys


def components(
    packages: list[dict[str, Any]],
    os: dict[str, Any],
    kernel: dict[str, Any],
    containers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for package in packages:
        raw = package.get("original_data", {})
        manager = package.get("package_manager", "")
        ecosystem = raw.get("ecosystem")
        if not ecosystem and manager in {"apt", "dpkg"}:
            ecosystem = {"ubuntu": "Ubuntu", "debian": "Debian"}.get(
                os.get("distribution", "").lower()
            )
        # Ecosystem is derived only from an unambiguous package manager.
        ecosystem = ecosystem or {"npm": "npm", "cargo": "crates.io", "pip": "PyPI"}.get(manager)
        result.append(
            {
                **package,
                "id": str(package["id"]),
                "kind": "package",
                "context": "host",
                "ecosystem": ecosystem,
                "distribution": os.get("distribution"),
                "release": os.get("release"),
                "vendor": raw.get("vendor"),
                "product": raw.get("product"),
                "cpe": raw.get("cpe"),
                "purl": raw.get("purl"),
                "adapter": raw.get("version_type"),
                "comparison_version": (
                    (str(package["epoch"]) + ":" + package["version"])
                    if manager == "rpm"
                    and package.get("epoch") is not None
                    and ":" not in package["version"]
                    else package["version"]
                ),
                "channel": raw.get("security_channel"),
            }
        )
    if kernel.get("version_raw"):
        result.append(
            {
                "id": "running-kernel",
                "kind": "kernel",
                "context": "running-kernel",
                "name": "linux",
                "version": kernel["version_raw"],
                "kernel_mapping": False,
            }
        )
    for container in containers:
        result.append(
            {
                "id": container["container_id"],
                "kind": "container",
                "context": "container:" + container["container_id"],
                "image_digest": container.get("image_digest"),
                "version": None,
                "name": container.get("image_reference"),
                "sbom_available": False,
            }
        )
    return result


def component_keys(component: dict[str, Any]) -> set[str]:
    keys = {"name:" + str(component.get("name", ""))}
    if component.get("source_package"):
        keys.add("source:" + component["source_package"])
        if component.get("ecosystem") in {"Ubuntu", "Debian"}:
            keys.add("osv-source:" + component["ecosystem"] + ":" + component["source_package"])
    if component.get("ecosystem") and component.get("name"):
        keys.add(
            "osv:"
            + component["ecosystem"]
            + ":"
            + ecosystem_name(component["ecosystem"], component["name"])
        )
    if component.get("vendor") and component.get("product"):
        keys.add("product:" + component["vendor"].lower() + ":" + component["product"].lower())
    if component.get("purl"):
        key = purl_key(component["purl"])
        if key:
            keys.add("purl:" + key)
    if component.get("cpe"):
        keys.add("cpe-wildcard")
        with contextlib.suppress(ValueError):
            keys.add("cpe:" + ":".join(parts(component["cpe"])[:3]).lower())
    return keys


def ubuntu(
    component: dict[str, Any],
    package: dict[str, Any],
    *,
    verified: bool = False,
) -> tuple[Status, str]:
    if str(component.get("distribution", "")).lower() != "ubuntu":
        return "unknown", "distribution_mismatch"
    if not component.get("source_package") or component["source_package"] != package.get("name"):
        return "potentially_affected", "source_package_unproven"
    release = component.get("release")
    release = {"20.04": "focal", "22.04": "jammy", "24.04": "noble"}.get(str(release), release)
    statuses = [s for s in package.get("statuses", []) if s.get("release_codename") == release]
    if not statuses:
        return "unknown", "release_evidence_missing"
    answers: list[tuple[Status, str]] = []
    for entry in statuses:
        if entry.get("architecture") and entry["architecture"] != component.get("architecture"):
            answers.append(("unknown", "architecture_mismatch"))
            continue
        channel = entry.get("pocket", entry.get("channel"))
        if channel and channel != component.get("channel"):
            answers.append(("unknown", "security_channel_unproven"))
            continue
        status = str(entry.get("status", "")).lower().replace(" ", "_")
        if status in {"released", "fixed"}:
            version = component.get("source_version")
            if not version:
                answers.append(("potentially_affected", "source_version_unproven"))
                continue
            try:
                d = compare("debian", version or "", entry.get("description", ""))
            except VersionError:
                answers.append(("potentially_affected", "invalid_or_missing_version"))
                continue
            if d < 0:
                answers.append(("affected", "ubuntu_below_fixed"))
            else:
                answers.append(
                    ("not_affected", "ubuntu_fixed_backport")
                    if verified
                    else ("potentially_affected", "ubuntu_api_requires_verified_negative")
                )
        elif status in {"not-affected", "not_affected", "dne", "not_in_release"}:
            answers.append(
                ("not_affected", "ubuntu_explicit_negative")
                if verified
                else ("unknown", "ubuntu_api_requires_verified_negative")
            )
        elif status in {"needed", "vulnerable"}:
            answers.append(("affected", "ubuntu_explicit_vulnerable"))
        else:
            answers.append(
                (
                    "unknown",
                    "ubuntu_"
                    + (
                        status
                        if status in {"ignored", "deferred", "pending", "needs_evaluation"}
                        else "needs_evaluation"
                    ),
                )
            )
    return answers[0] if len(set(answers)) == 1 else ("unknown", "conflicting_ubuntu_status")


def cna_status(value: Any) -> Status:
    return (
        "affected"
        if value == "affected"
        else "not_affected"
        if value == "unaffected"
        else "unknown"
    )


def cna(component: dict[str, Any], value: dict[str, Any]) -> tuple[Status, str, str | None]:
    if not all(
        component.get(k) and str(component[k]).lower() == str(value.get(k, "")).lower()
        for k in ["vendor", "product"]
    ):
        return "potentially_affected", "product_identity_unproven", None
    if any(value.get(k) for k in ["modules", "programFiles", "programRoutines"]):
        return "unknown", "product_conditions_unproven", None
    if value.get("platforms") and component.get("platform") not in value["platforms"]:
        return "unknown", "platform_unproven", None
    version = component.get("comparison_version", component.get("version"))
    if not version:
        return "potentially_affected", "missing_version", None
    decisions: list[Status] = []
    unsupported = False
    adapter_used = None
    versions = value.get("versions", [])
    if len(versions) > 4096:
        raise EvaluationLimit("cna_versions_limit")
    for row in versions:
        adapter = {"semver": "semver", "rpm": "rpm", "dpkg": "debian", "debian": "debian"}.get(
            row.get("versionType")
        )
        adapter_used = adapter or adapter_used
        has_range = "lessThan" in row or "lessThanOrEqual" in row
        if not has_range:
            applies = version == row.get("version")
        elif adapter:
            try:
                start, end = row.get("version", ""), row.get("lessThan", row.get("lessThanOrEqual"))
                applies = (start == "0" or compare(adapter, version, start) >= 0) and (
                    end == "*"
                    or (
                        compare(adapter, version, end) < 0
                        if "lessThan" in row
                        else compare(adapter, version, end) <= 0
                    )
                )
            except VersionError:
                unsupported = True
                continue
        else:
            unsupported = True
            continue
        if not applies:
            continue
        status = row.get("status", "unknown")
        changes = row.get("changes", [])
        if changes:
            if not adapter:
                unsupported = True
                continue
            try:
                previous = row.get("version", "0")
                for change in changes:
                    boundary = change.get("at", "")
                    if previous != "0" and compare(adapter, previous, boundary) > 0:
                        raise VersionError("invalid_range")
                    previous = boundary
                    if compare(adapter, version, boundary) >= 0:
                        status = change.get("status", "unknown")
            except VersionError:
                unsupported = True
                continue
        decisions.append(cna_status(status))
    if unsupported:
        return "potentially_affected", "unsupported_cna_range", adapter_used
    if decisions:
        return (
            (decisions[0], "cna_version_status", adapter_used)
            if len(set(decisions)) == 1
            else ("unknown", "conflicting_cna_status", adapter_used)
        )
    return (
        cna_status(value.get("defaultStatus")),
        "cna_default_status",
        adapter_used,
    )


def evaluate(
    enrichment: dict[str, Any], inventory: list[dict[str, Any]], sections: dict[str, str]
) -> Evaluation:
    if len(enrichment.get("affected", [])) > 4096:
        raise EvaluationLimit("expression_limit")
    decisions: list[Decision] = []
    coverage: dict[str, Any] = {
        "sections": sections,
        "scope": "snapshot",
        "unmapped_assertions": 0,
        "container_packages": "inventoried"
        if any(
            c.get("context", "").startswith("container:") and c["kind"] == "package"
            for c in inventory
        )
        else "unavailable",
        "running_kernel": "unmapped",
        "global_negative": False,
    }
    if enrichment.get("lifecycle", {}).get("value") in {"rejected", "withdrawn"}:
        return Evaluation(
            status="not_applicable",
            reason="cve_lifecycle_excluded",
            components=[],
            coverage=coverage,
        )
    indexed: dict[str, dict[str, dict[str, Any]]] = {}
    for component in inventory:
        for key in component_keys(component):
            indexed.setdefault(key, {})[component["id"]] = component
    for position, item in enumerate(enrichment.get("affected", [])):
        reference = {
            "kind": item.get("kind"),
            "provenance": item.get("provenance", {}),
            "enrichment_assertion": "/affected/" + str(position),
            "assertion_sha256": digest(item),
        }
        value, kind = item.get("value", {}), item.get("kind", "")
        keys = source_keys([item])
        candidates = list(
            {cid: c for key in sorted(keys) for cid, c in indexed.get(key, {}).items()}.values()
        )
        if kind == "nvd_configuration_logic":
            identities = [
                {"cpe": c["cpe"], "adapter": c.get("adapter")} for c in inventory if c.get("cpe")
            ]
            trees = value if isinstance(value, list) else [value]
            # Inventory v1.1 does not claim exhaustive CPE identity coverage.
            evaluations = [
                configuration(t, identities, False) for t in trees if isinstance(t, dict)
            ]
            proven = item.get("matching_usable", False) and any(
                t is True and v for t, v in evaluations
            )
            status: Status = (
                "affected" if proven else "potentially_affected" if candidates else "unknown"
            )
            decisions.append(
                Decision(
                    component_id="configuration:" + digest(value),
                    status=status,
                    reason="nvd_applicability" if proven else "nvd_context_incomplete",
                    rule_id="nvd-three-valued-1",
                    evidence=[reference],
                )
            )
            continue
        if not candidates:
            coverage["unmapped_assertions"] += 1
            continue
        if len(decisions) + len(candidates) > 16384:
            raise EvaluationLimit("decision_limit")
        for component in candidates:
            status, reason, adapter = "unknown", "unsupported_evidence", None
            operand = component.get("comparison_version", component.get("version"))
            if not item.get("matching_usable", False):
                status, reason = "potentially_affected", "ambiguous_or_inactive_source"
            elif component["kind"] != "package":
                status, reason = "unknown", "kernel_or_container_mapping_unavailable"
            elif kind == "osv_package":
                package = value.get("package", {})
                exact = component.get("ecosystem") == package.get("ecosystem") and component.get(
                    "name"
                ) == package.get("name")
                if component.get("ecosystem") == package.get("ecosystem") == "PyPI":
                    exact = ecosystem_name("PyPI", component.get("name", "")) == ecosystem_name(
                        "PyPI", package.get("name", "")
                    )
                ecosystem = package.get("ecosystem", "")
                if ecosystem.split(":")[0] in {"Ubuntu", "Debian"}:
                    fields = ecosystem.split(":")
                    distro = fields[0]
                    release = (
                        fields[2]
                        if len(fields) > 2 and fields[1] == "Pro"
                        else fields[1]
                        if len(fields) > 1
                        else None
                    )
                    exact = component.get("ecosystem") == distro and component.get(
                        "source_package"
                    ) == package.get("name")
                    exact = exact and (release is None or release == component.get("release"))
                    exact = exact and (
                        distro != "Ubuntu"
                        or bool(
                            re.fullmatch(r"Ubuntu:(?:Pro:)?[0-9]{2}\.[0-9]{2}(?::LTS)?", ecosystem)
                        )
                    )
                    if "Pro" in fields and component.get("channel") != "esm":
                        exact = False
                    operand = component.get("source_version")
                purl = purl_key(package.get("purl", ""))
                if (
                    not exact
                    and purl
                    and component.get("purl")
                    and ecosystem.split(":")[0] not in {"Ubuntu", "Debian"}
                ):
                    exact = purl == purl_key(component["purl"])
                if exact:
                    answer, reason, adapter = osv(operand, value)
                    status = (
                        "affected"
                        if answer is True
                        else "not_affected"
                        if answer is False
                        else "potentially_affected"
                    )
                else:
                    status, reason = "potentially_affected", "ecosystem_identity_unproven"
            elif str(kind).startswith("ubuntu_"):
                packages = value if isinstance(value, list) else [value]
                answers = [
                    ubuntu(component, p)
                    for p in packages
                    if p.get("name") in {component.get("name"), component.get("source_package")}
                ]
                status, reason = (
                    answers[0] if len(answers) == 1 else ("unknown", "ambiguous_ubuntu_evidence")
                )
                adapter = "debian"
                operand = component.get("source_version")
            elif kind == "cna_product":
                status, reason, adapter = cna(component, value)
            decisions.append(
                Decision(
                    component_id=component["id"],
                    context=component.get("context", "host"),
                    installed_version=component.get("version"),
                    comparison_version=operand,
                    status=status,
                    reason=reason,
                    rule_id=str(kind) + "-1",
                    adapter=adapter,
                    evidence=[
                        reference
                        | (
                            {
                                "component": {
                                    k: component.get(k)
                                    for k in [
                                        "name",
                                        "container_name",
                                        "image_id",
                                        "origin",
                                        "target",
                                    ]
                                }
                            }
                            if component.get("context", "").startswith("container:")
                            else {}
                        )
                    ],
                )
            )
    # Equal-scope contradictory outcomes remain explicit, never a source vote.
    by_component: dict[str, list[Decision]] = {}
    for decision in decisions:
        by_component.setdefault(decision.component_id, []).append(decision)
    resolved: list[Decision] = []
    for group in by_component.values():
        positive = any(d.status == "affected" for d in group)
        negative = any(d.status == "not_affected" for d in group)
        # A matching distro fix boundary constrains generic upstream assertions.
        distro_uncertain = any(d.reason == "ubuntu_api_requires_verified_negative" for d in group)
        if (positive and negative) or (positive and distro_uncertain):
            resolved.append(
                Decision(
                    component_id=group[0].component_id,
                    context=group[0].context,
                    installed_version=group[0].installed_version,
                    status="potentially_affected",
                    reason="conflicting_sources",
                    rule_id="evidence-conflict-1",
                    evidence=[e for d in group for e in d.evidence],
                    conflicts=[d.model_dump(mode="json") for d in group],
                )
            )
        else:
            resolved.extend(group)
    resolved = [
        d.model_copy(
            update={
                "data_quality": "conflicted"
                if d.conflicts
                else "complete"
                if d.status in {"affected", "not_affected"}
                else "partial"
            }
        )
        for d in resolved
    ]
    if any(d.status == "affected" for d in resolved):
        aggregate: Status = "affected"
        reason = "confirmed_component"
    elif any(d.status == "potentially_affected" for d in resolved):
        aggregate, reason = "potentially_affected", "incomplete_or_conflicting_evidence"
    else:
        # No exhaustive software/kernel/container identity coverage in inventory 1.1.
        aggregate, reason = "unknown", "global_coverage_incomplete"
    return Evaluation(
        status=aggregate,
        reason=reason,
        components=resolved,
        coverage=coverage,
        data_quality="conflicted" if any(d.conflicts for d in resolved) else "partial",
    )
