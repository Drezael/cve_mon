"""Internal HTTPS inventory client; public deployments use the Dashboard file upload."""

import argparse
import hashlib
import json
import os
import ssl
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from cve_automation.inventory_adapter import MAX_BYTES, decode, validate
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from scripts.ansible.manage import ROOT, private_json, secret


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def request(
    config: dict[str, Any],
    path: str,
    raw: bytes | None = None,
    *,
    key: str | None = None,
) -> dict[str, Any]:
    origin = config["origin"]
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Exact HTTPS inventory origin required")
    if not path.startswith("/api/v1/inventories") or ".." in path or "?" in path:
        raise ValueError("Fixed internal inventory endpoint required")
    context = ssl.create_default_context(cafile=config["ca_file"])
    secret(config["key_file"])
    context.load_cert_chain(config["certificate_file"], config["key_file"])
    token = secret(config["token_file"])
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    if key:
        headers["Idempotency-Key"] = key
    call = urllib.request.Request(
        origin + path,
        data=raw,
        headers=headers,
        method="POST" if raw is not None else "GET",
    )
    client = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    with client.open(call, timeout=30) as response:
        value = json.loads(response.read(1024 * 1024 + 1))
    if not isinstance(value, dict):
        raise ValueError("Inventory response must be an object")
    return value


def submit(config: dict[str, Any], raw: bytes) -> dict[str, Any]:
    document = decode(raw)
    validate(document)
    identity = document["host"]["monitoring_id"] if "host" in document else document["server_id"]
    digest = hashlib.sha256(raw).hexdigest()
    key = "inv1:" + identity + ":" + digest
    result = request(config, "/api/v1/inventories", raw, key=key)
    schema = json.loads((ROOT / "contracts/inventory/submission-response.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    if result["inventory_id"] != document["inventory_id"] or result["source"] != "ansible_api":
        raise ValueError("Unexpected inventory acknowledgement")
    if result["status_url"] != "/api/v1/inventories/submissions/" + result["submission_id"]:
        raise ValueError("Unexpected inventory status URL")
    if config.get("receipt_root"):
        directory = Path(config["receipt_root"]) / str(UUID(result["server_id"]))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = directory / (digest + ".receipt.json")
        receipt = {**result, "idempotency_key": key, "inventory_sha256": digest}
        with tempfile.NamedTemporaryFile(dir=directory, mode="w", delete=False) as stream:
            temporary = Path(stream.name)
            try:
                json.dump(receipt, stream)
                stream.flush()
                os.fsync(stream.fileno())
                try:
                    os.link(temporary, target)
                except FileExistsError:
                    existing = private_json(target)
                    if any(
                        existing.get(k) != receipt[k]
                        for k in (
                            "submission_id",
                            "inventory_id",
                            "server_id",
                            "inventory_sha256",
                        )
                    ):
                        raise ValueError("Conflicting immutable inventory receipt") from None
            finally:
                temporary.unlink(missing_ok=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--file", type=Path)
    parser.add_argument("--status", type=UUID)
    args = parser.parse_args()
    if bool(args.file) == bool(args.status):
        parser.error("Select exactly one inventory file or status UUID")
    try:
        config = private_json(args.config)
        if args.status:
            result = request(config, "/api/v1/inventories/submissions/" + str(args.status))
        else:
            with args.file.open("rb") as stream:
                result = submit(config, stream.read(MAX_BYTES + 1))
        print(json.dumps(result))
    except urllib.error.HTTPError as error:
        print(json.dumps({"http_status": error.code}))
        raise SystemExit(1) from None
    except (OSError, ValueError, ValidationError):
        raise SystemExit(
            "Inventory transfer failed; check private credentials and internal endpoint"
        ) from None


if __name__ == "__main__":
    main()
