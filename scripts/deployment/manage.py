"""Release and deployment CLI. Production authorization is external and never inferred."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

from scripts.deployment import artifacts, maintenance, orchestration, preflight, recovery, release
from scripts.deployment.contracts import environment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "stage",
            "build",
            "release",
            "export-images",
            "import-images",
            "prepare",
            "preflight",
            "deploy",
            "smoke",
            "restart",
            "backup",
            "restore-test",
            "recover",
        ],
    )
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--recovery-environment", type=Path)
    parser.add_argument("--staging-evidence", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "build":
            from scripts.deployment.build import run

            run()
            print(json.dumps({"built": True, "deployed": False}))
            return
        if args.action == "stage":
            if args.directory is None:
                parser.error("--directory required")
            target = orchestration.stage(args.directory)
            print(
                json.dumps({"environment_file": str(target.path), "project": target.config.project})
            )
            return
        if args.bundle is None:
            parser.error("--bundle required")
        if args.action == "release":
            if args.version is None:
                parser.error("--version required")
            value = release.create(args.version, args.bundle)
            print(
                json.dumps(
                    {
                        "release_id": value["release_id"],
                        "production_eligible": value["production_eligible"],
                    }
                )
            )
            return
        if args.action in {"export-images", "import-images"}:
            if args.directory is None:
                parser.error("--directory required")
            if args.action == "export-images":
                result = artifacts.export(args.bundle, args.directory)
                print(json.dumps({"exported_images": len(result["images"])}))
            else:
                artifacts.import_images(args.bundle, args.directory)
                print(json.dumps({"imported_images": len(release.verify(args.bundle)["images"])}))
            return
        if args.environment is None:
            parser.error("--environment required")
        target = environment(args.environment)
        if args.action == "prepare":
            target = orchestration.pinned(target, args.bundle)
            orchestration.prepare(target, args.bundle)
            print(json.dumps({"prepared": True, "project": target.config.project}))
            return
        manifest = release.verify(args.bundle, current_source=True)
        overlay = target.control / ("images-" + manifest["release_id"] + ".json")
        if not overlay.is_file():
            raise ValueError("Explicit release preparation required")
        target = replace(target, config=replace(target.config, compose_overrides=(overlay,)))
        if args.action in {"backup", "restore-test", "recover"}:
            if args.key_file is None or args.backup is None:
                parser.error("--key-file and --backup required")
            if args.action == "backup":
                value = recovery.snapshot(
                    target,
                    args.bundle,
                    args.backup,
                    args.key_file,
                    approval=args.approval,
                    staging_evidence=args.staging_evidence,
                )
            elif args.action == "restore-test":
                if target.kind == "production":
                    from scripts.deployment.state import authorize

                    authorize(
                        target,
                        manifest,
                        args.approval,
                        args.staging_evidence,
                        action="restore-test",
                    )
                value = recovery.restore_database_test(target, args.backup, args.key_file)
            else:
                if args.directory is None and args.recovery_environment is None:
                    parser.error("--directory or --recovery-environment required")
                recovered = (
                    environment(args.recovery_environment)
                    if args.recovery_environment
                    else orchestration.stage(args.directory)
                )
                value = recovery.recover_stage(
                    target,
                    recovered,
                    args.bundle,
                    args.backup,
                    args.key_file,
                    approval=args.approval,
                    staging_evidence=args.staging_evidence,
                )
            print(json.dumps(value))
            return
        if args.action == "restart":
            value = maintenance.restart(
                target, args.bundle, approval=args.approval, staging_evidence=args.staging_evidence
            )
        elif args.action == "preflight":
            value = preflight.check(target, args.bundle, prepared=not args.bootstrap)
        elif args.action == "smoke":
            value = orchestration.smoke(target, args.bundle)
        else:
            value = orchestration.rollout(
                target,
                args.bundle,
                approval=args.approval,
                staging_evidence=args.staging_evidence,
                dry_run=args.dry_run,
            )
        print(json.dumps(value))
    except Exception as error:
        # Never serialize subprocess command/env/output; credentials can appear there.
        print(json.dumps({"passed": False, "error_type": type(error).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
