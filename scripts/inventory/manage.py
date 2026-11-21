"Read-only inventory contract, mTLS, credential metadata, receipt and isolation inspection."

import argparse
import hashlib
import json
from pathlib import Path
from uuid import UUID

import psycopg
from cve_api.inventories.errors import UploadError
from cve_api.technical_auth.certificates import crl
from jsonschema import Draft202012Validator

from scripts.database.manage import connect
from scripts.infrastructure.manage import load_config, resolved, validate_model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["contract", "mtls", "submission", "credentials", "permissions", "metrics"],
    )
    parser.add_argument("--submission-id", type=UUID)
    args = parser.parse_args()
    try:
        cfg = load_config()
        result: dict[str, object] = {}
        if args.action == "contract":
            from importlib.resources import files

            hashes = {}
            for version, filename in [
                ("1.0", "inventory-v1.schema.json"),
                ("1.1", "inventory-v1.1.schema.json"),
            ]:
                original = cfg.root / "contracts/inventory" / filename
                Draft202012Validator.check_schema(json.loads(original.read_text()))
                assert (
                    files("cve_api.inventories").joinpath("data/" + filename).read_bytes()
                    == original.read_bytes()
                )
                hashes[version] = "sha256:" + hashlib.sha256(original.read_bytes()).hexdigest()
            result = {"supported_versions": ["1.0", "1.1"], "schema_hashes": hashes}
        elif args.action == "mtls":
            revoked = crl(Path(cfg.values["CLIENT_CRL_FILE"]), Path(cfg.values["CLIENT_CA_FILE"]))
            template = (
                cfg.root / "infrastructure/nginx/conf.d/30-inventory.conf.template"
            ).read_text()
            assert "ssl_verify_client on;" in template and "ssl_crl " in template
            snippet = (cfg.directory / "snippets/inventory-technical-routes.conf").read_text()
            assert (
                "$ssl_client_escaped_cert" in snippet
                and "$ssl_client_verify" in snippet
                and "X-CVE-Inventory-Gateway" in snippet
            )
            assert not validate_model(
                resolved(cfg),
                cfg.values["APP_ENV"] == "development",
                cfg.root,
                mount_base=cfg.mount_base,
                secrets_base=cfg.secrets_base,
            )
            assert revoked.next_update_utc is not None
            result = {
                "mtls": "required",
                "crl_next_update": revoked.next_update_utc.isoformat(),
                "backend": "private_capability",
                "fingerprint": "SHA-256 DER",
            }
        else:
            with connect(cfg) as c:
                c.execute("SET TRANSACTION READ ONLY")
                if args.action == "submission":
                    if args.submission_id is None:
                        raise ValueError("Explicit submission UUID required")
                    row = c.execute(
                        "SELECT id,inventory_id,server_id,source,source_identity,schema_ve"
                        "rsion,status,received_at,collected_at,payload_size,encode(payload"
                        "_sha256,'hex') AS payload_sha256 FROM inventory.submissions WHERE"
                        " id=%s",
                        (args.submission_id,),
                    ).fetchone()
                    if row is None:
                        raise ValueError("Submission not found")
                    result = {"submission": row}
                elif args.action == "credentials":
                    result = {
                        "limit": 100,
                        "clients": c.execute(
                            "SELECT id,name,status,created_at FROM security.technical_principa"
                            "ls ORDER BY id LIMIT 100"
                        ).fetchall(),
                        "certificates": c.execute(
                            "SELECT id,principal_id,expires_at,revoked_at,expires_at<clock_tim"
                            "estamp()+interval '7 days' AS expiring FROM security.technical_ce"
                            "rtificates ORDER BY id LIMIT 100"
                        ).fetchall(),
                        "tokens": c.execute(
                            "SELECT id,principal_id,server_id,certificate_id,expires_at,revoke"
                            "d_at,disabled,last_used_at FROM security.api_tokens WHERE runtime"
                            "_version=1 ORDER BY id LIMIT 100"
                        ).fetchall(),
                    }
                elif args.action == "permissions":
                    for role in ["api_ingest", "api_security"]:
                        attrs = c.execute(
                            "SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb A"
                            "S elevated FROM pg_roles WHERE rolname=%s",
                            (role,),
                        ).fetchone()
                        assert attrs and not attrs["elevated"], "Elevated runtime role"
                        for column in ["payload_raw", "payload_json"]:
                            row = c.execute(
                                "SELECT has_column_privilege(%s,'inventory.submissions',"
                                "%s,'SELECT') AS allowed",
                                (role, column),
                            ).fetchone()
                            assert row is not None and not row["allowed"], (
                                "Full payload read forbidden"
                            )
                        row = c.execute(
                            "SELECT has_table_privilege(%s,'inventory.submissions',"
                            "'INSERT') AS allowed",
                            (role,),
                        ).fetchone()
                        assert row and row["allowed"]
                    for role in [
                        "api_ingest",
                        "inventory_processor",
                        "matcher",
                        "event_dispatcher",
                    ]:
                        for table, column in [
                            ("inventory.servers", "primary_group_id"),
                            ("inventory.servers", "display_order"),
                            ("inventory.server_groups", "sort_order"),
                        ]:
                            row = c.execute(
                                "SELECT has_column_privilege(%s,%s,%s,'UPDATE') AS allowed",
                                (role, table, column),
                            ).fetchone()
                            assert row is not None and not row["allowed"], (
                                "Administrative write forbidden"
                            )
                    result = {
                        "permissions": "isolated",
                        "payload_reads": "operator_only",
                        "api_superuser": False,
                    }
                result["metrics"] = c.execute(
                    "SELECT security.inventory_metrics() AS metrics"
                ).fetchone()
        print(json.dumps({"result": "ok", "action": args.action, **result}, default=str))
        return 0
    except (OSError, ValueError, AssertionError, psycopg.Error, UploadError) as error:
        print(json.dumps({"result": "error", "action": args.action, "code": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
