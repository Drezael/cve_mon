"""Pinned scanner, immutable image inputs, SBOMs and explicit fail-closed vulnerability gates."""

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.infrastructure.manage import docker_command, load_config, run

VERSION = "0.76.2"
ARCHIVE_SHA256 = (
    "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"  # pragma: allowlist secret
)
ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".runtime/hardening"
REPORTS = ROOT / ".runtime/test-reports/phase-23-supply-chain"


def input_hashes() -> dict[str, str]:
    paths = [
        ROOT / p
        for p in [
            "requirements/runtime.txt",
            "requirements/dev.txt",
            "requirements/native-build.txt",
            "services/dashboard/package-lock.json",
            "compose.yml",
            "infrastructure/images.lock.json",
            "infrastructure/application/native-packages.lock.json",
            "infrastructure/image-reviews.json",
            "infrastructure/n8n/bootstrap.cjs",
            "scripts/hardening/image_reviews.py",
        ]
    ]
    paths.extend(sorted((ROOT / "services").glob("*/Dockerfile")))
    paths.extend(sorted((ROOT / "infrastructure").glob("*/Dockerfile")))
    paths.extend(sorted((ROOT / "infrastructure").glob("*/packages.lock.json")))
    paths.extend(sorted((ROOT / "infrastructure").glob("*/artifacts.lock.json")))
    paths.extend(
        ROOT / p for p in ["scripts/hardening/runtime_images.py", "scripts/services/wheels.py"]
    )
    from scripts.application.build import fingerprint

    values = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    values["application-source-inputs"] = fingerprint(ROOT)
    return values


def scanner() -> Path:
    executable = WORK / "tools/trivy"
    result = subprocess.run(
        [str(executable), "--version", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if json.loads(result.stdout)["Version"] != VERSION:
        raise ValueError("Pinned Trivy version required; see supply-chain-security.md")
    archive = WORK / "tools/trivy.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Scanner distribution checksum mismatch")
    # Verify installed bytes too, not only the downloaded distribution.
    with tarfile.open(archive) as source:
        member = source.extractfile("trivy")
        if (
            member is None
            or hashlib.sha256(member.read()).digest()
            != hashlib.sha256(executable.read_bytes()).digest()
        ):
            raise ValueError("Installed scanner differs from verified distribution")
    return executable


def gate(report: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(report.get("Results"), list) or not report["Results"]:
        raise ValueError("Incomplete vulnerability report; no automatic clean result")
    if not any(r.get("Class") in {"os-pkgs", "lang-pkgs"} for r in report["Results"]):
        raise ValueError("No package scan coverage")
    findings = []
    for result in report["Results"]:
        if result.get("Class") == "secret":
            for secret in result.get("Secrets", []):
                findings.append(
                    {
                        "target": result["Target"],
                        "id": secret["RuleID"],
                        "package": "embedded-secret",
                        "installed": "image",
                        "severity": secret["Severity"],
                        "fixed": "remove and rotate",
                    }
                )
            continue
        if (
            not isinstance(result.get("Target"), str)
            or result.get("Class") not in {"os-pkgs", "lang-pkgs"}
            or not isinstance(result.get("Type"), str)
            or not isinstance(result.get("Packages"), list)
            or not result["Packages"]
        ):
            raise ValueError("Missing package inventory or scanner coverage")
        for item in result.get("Vulnerabilities", []):
            if item["Severity"] in {"HIGH", "CRITICAL", "UNKNOWN"}:
                findings.append(
                    {
                        "target": result["Target"],
                        "id": item["VulnerabilityID"],
                        "package": item["PkgName"],
                        "installed": item["InstalledVersion"],
                        "severity": item["Severity"],
                        "fixed": item.get("FixedVersion", ""),
                    }
                )
    return findings


def execute(arguments: list[str], target: Path) -> None:
    target.unlink(missing_ok=True)
    partial = target.with_suffix(target.suffix + ".partial")
    partial.unlink(missing_ok=True)
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    subprocess.run(
        [
            str(scanner()),
            *arguments,
            "--cache-dir",
            str(WORK / "cache"),
            "--no-progress",
            "--output",
            str(partial),
        ],
        check=True,
        timeout=1800,
    )
    value = json.loads(partial.read_text())
    if not isinstance(value, dict):
        raise ValueError("Invalid scanner output")
    # Never publish matched secret bytes or source-code excerpts as CI artifacts.
    for result in value.get("Results", []):
        if "Secrets" in result:
            result["Secrets"] = [
                {
                    k: v
                    for k, v in item.items()
                    if k in {"RuleID", "Category", "Severity", "Title", "StartLine", "EndLine"}
                }
                for item in result["Secrets"]
            ]
    partial.write_text(json.dumps(value, indent=2))
    partial.chmod(0o600)
    partial.replace(target)


def dependencies() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    (REPORTS / "dependency-gate.json").unlink(missing_ok=True)
    inputs = input_hashes()
    findings = []
    for name in ["runtime", "dev", "frontend", "native-build"]:
        source = WORK / "dependency-inputs" / name
        source.mkdir(parents=True, exist_ok=True)
        if name == "frontend":
            package_root = ROOT / "services/dashboard"
            shutil.copyfile(package_root / "package-lock.json", source / "package-lock.json")
            shutil.copyfile(package_root / "package.json", source / "package.json")
        else:
            shutil.copyfile(ROOT / f"requirements/{name}.txt", source / "requirements.txt")
        target = REPORTS / f"dependencies-{name}.json"
        execute(
            ["fs", "--scanners", "vuln", "--include-dev-deps", "--format", "json", str(source)],
            target,
        )
        findings.extend(gate(json.loads(target.read_text())))
        execute(["fs", "--format", "cyclonedx", str(source)], REPORTS / f"sbom-{name}.cdx.json")
    if input_hashes() != inputs:
        raise ValueError("Dependency inputs changed during scan")
    result = {
        "scanner": VERSION,
        "input_hashes": inputs,
        "checked_at": datetime.now(UTC).isoformat(),
        "blocking_findings": findings,
        "exceptions": [],
    }
    (REPORTS / "dependency-gate.json").write_text(json.dumps(result, indent=2))
    if findings:
        raise ValueError(
            f"Dependency gate: {len(findings)} unresolved high/critical/unknown findings"
        )


def images() -> None:
    """Host operator exports images; scanner receives archives, never a container socket mount."""
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg = load_config()
    from scripts.infrastructure.manage import resolved, validate_model

    model = resolved(cfg)
    errors = validate_model(
        model,
        cfg.values["APP_ENV"] == "development",
        cfg.root,
        mount_base=cfg.mount_base,
        secrets_base=cfg.secrets_base,
    )
    if errors:
        raise ValueError("Validated 7-service model required for artifact inventory")
    services = [
        {"Service": name, "Image": value["image"]} for name, value in model["services"].items()
    ]
    (REPORTS / "image-gate.json").unlink(missing_ok=True)
    inputs = input_hashes()
    inventory = []
    findings = []
    accepted = []
    for service in services:
        name = service["Service"]
        # Inspect only image identity/configuration; never container environment/credentials.
        # Resolve the candidate artifact once; subsequent scan/export uses only its immutable ID.
        reference = service["Image"]
        metadata = json.loads(run([*docker_command(), "image", "inspect", reference]).stdout)[0]
        from scripts.application.build import LABEL, fingerprint
        from scripts.infrastructure.topology import GROUPS

        if name in GROUPS and metadata["Config"].get("Labels", {}).get(LABEL) != fingerprint(ROOT):
            raise ValueError("Build the current application source before scanning: " + name)
        identity = metadata["Id"]
        archive = WORK / (name + ".tar")
        try:
            run([*docker_command(), "image", "save", "--output", str(archive), identity])
            # Docker through sudo owns exported files; allow this operator to read its own archive.
            if os.environ.get("CVE_DOCKER_SUDO") == "1":
                run(
                    ["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(archive)]
                )
            archive.chmod(0o600)
            config_digests = []
            with tarfile.open(archive) as exported:
                manifest_stream = exported.extractfile("manifest.json")
                if manifest_stream is None:
                    raise ValueError("Docker export manifest required")
                for entry in json.loads(manifest_stream.read(1048576)):
                    config_stream = exported.extractfile(entry["Config"])
                    if config_stream is None:
                        raise ValueError("Image config required")
                    config_bytes = config_stream.read(1048577)
                    if len(config_bytes) > 1048576:
                        raise ValueError("Oversized image config")
                    config_digests.append("sha256:" + hashlib.sha256(config_bytes).hexdigest())
            arguments = [
                "image",
                "--input",
                str(archive),
                "--scanners",
                "vuln,secret",
                "--format",
                "json",
            ]
            target = REPORTS / (name + "-vulnerabilities.json")
            execute(arguments, target)
            from scripts.hardening.image_reviews import apply

            blocked, reviewed = apply(json.loads(target.read_text()), reference, ROOT)
            findings.extend(blocked)
            accepted.extend(reviewed)
            execute(
                ["image", "--input", str(archive), "--format", "cyclonedx"],
                REPORTS / (name + "-sbom.cdx.json"),
            )
        finally:
            archive.unlink(missing_ok=True)
        inventory.append(
            {
                "service": name,
                "reference": reference,
                "image_id": identity,
                "config_digests": sorted(config_digests),
                "repo_digests": metadata.get("RepoDigests", []),
                "created": metadata["Created"],
            }
        )
        (REPORTS / "image-inventory.json").write_text(json.dumps(inventory, indent=2))
    if input_hashes() != inputs:
        raise ValueError("Image source inputs changed during scan")
    (REPORTS / "image-gate.json").write_text(
        json.dumps(
            {
                "scanner": VERSION,
                "input_hashes": inputs,
                "checked_at": datetime.now(UTC).isoformat(),
                "blocking_findings": findings,
                "exceptions": accepted,
                "scanned_services": len(inventory),
            },
            indent=2,
        )
    )
    if findings:
        raise ValueError(f"Image gate: {len(findings)} unresolved high/critical/unknown findings")
