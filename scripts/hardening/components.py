"""Inspect embedded libraries that OS/package vulnerability scanners cannot resolve."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.hardening import supply_chain
from scripts.infrastructure.manage import docker_command, run

PYTHON = """import importlib.util,json,sqlite3,ssl,pyexpat
v=dict(sqlite=sqlite3.sqlite_version,expat=pyexpat.EXPAT_VERSION,openssl=ssl.OPENSSL_VERSION)
if importlib.util.find_spec("psycopg"):
 import psycopg.pq
 assert psycopg.pq.__impl__ == "binary",v
 v.update(driver=psycopg.pq.__impl__,libpq=psycopg.pq.version())
if importlib.util.find_spec("cryptography"):
 from cryptography.hazmat.backends.openssl.backend import backend
 v["cryptography_openssl"] = backend.openssl_version_text()
assert sqlite3.connect(":memory:").execute("select 1").fetchone() == (1,)
print(json.dumps(v))"""
NODE = """const assert=require('node:assert/strict');const v=process.versions;
const z=require('node:zlib');
assert.equal(z.brotliDecompressSync(z.brotliCompressSync(Buffer.from('ok'))).toString(),'ok');
console.log(JSON.stringify(v));"""


def policy_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def probe(identity: str, executable: str, arguments: list[str]) -> str:
    return run(
        [
            *docker_command(),
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65532:65532",
            "--entrypoint",
            executable,
            identity,
            *arguments,
        ]
    ).stdout.strip()


def verify(target: Path | None = None) -> dict[str, Any]:
    target = target or supply_chain.ROOT / ".runtime/test-reports/phase-23-components.json"
    target.unlink(missing_ok=True)
    inventory_path = supply_chain.REPORTS / "image-inventory.json"
    inventory = json.loads(inventory_path.read_text())
    if len(inventory) != 7 or len({v["service"] for v in inventory}) != 7:
        raise ValueError("Complete immutable image inventory required")
    results = []
    for item in inventory:
        name, identity = item["service"], item["image_id"]
        details: dict[str, Any]
        from scripts.infrastructure.images import REFERENCES

        vendor = {
            "cve-n8n": "n8n",
            "cve-postgres": "postgres",
            "cve-nginx": "nginx",
            "cve-mail-relay": "mail",
            "cve-mailhog": "mailhog",
        }
        if name in vendor:
            reference = REFERENCES[vendor[name]]
            original = run([*docker_command(), "image", "inspect", reference]).stdout
            if json.loads(original)[0]["Id"] != identity:
                raise ValueError("Vendor image differs from pinned original: " + name)
        else:
            base = json.loads(
                run([*docker_command(), "image", "inspect", REFERENCES["python"]]).stdout
            )[0]
            application = json.loads(run([*docker_command(), "image", "inspect", identity]).stdout)[
                0
            ]
            layers = base["RootFS"]["Layers"]
            if application["RootFS"]["Layers"][: len(layers)] != layers:
                raise ValueError("Application must extend the unchanged Python base")
        if name == "cve-n8n":
            output = probe(identity, "node", ["-e", NODE])
            details = {"versions": json.loads(output), "unmodified_upstream": True}
        elif name == "cve-postgres":
            output = probe(identity, "postgres", ["--version"])
            details = {"version": output, "unmodified_upstream": True}
        elif name == "cve-nginx":
            output = probe(identity, "/bin/sh", ["-ec", "nginx -v 2>&1"])
            details = {"version": output, "unmodified_upstream": True}
        elif name == "cve-mailhog":
            output = probe(identity, "MailHog", ["-version"])
            details = {"version": output, "unmodified_upstream": True}
        elif name == "cve-egress-proxy":
            output = probe(identity, "envoy", ["--version"])
            details = {"version": output, "unmodified_upstream": True}
        elif name == "cve-mail-relay":
            output = probe(
                identity, "postconf", ["-c", "/etc/postfix.default", "-h", "mail_version"]
            )
            details = {"version": output, "unmodified_upstream": True}
        else:
            output = probe(identity, "python", ["-c", PYTHON])
            details = {"versions": json.loads(output), "original_python_base": True}
        results.append(
            {
                "service": name,
                "image_id": identity,
                "probe_sha256": hashlib.sha256(output.encode()).hexdigest(),
                **details,
            }
        )
    value = {
        "checked_at": datetime.now(UTC).isoformat(),
        "passed": True,
        "inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "policy_sha256": policy_sha256(),
        "artifacts": results,
    }
    target.write_text(json.dumps(value, indent=2))
    target.chmod(0o600)
    return value


if __name__ == "__main__":
    print(json.dumps(verify()))
