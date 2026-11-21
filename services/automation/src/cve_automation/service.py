"""Fenced executor; decrypted SSH data exists only in private disposable work directories."""

import asyncio
import contextlib
import hashlib
import json
import os
import signal
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import Payload
from cve_common.jobs.errors import ErrorCode, LeaseLost
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.worker import WorkerSettings
from cve_common.ssh_credentials import SSHKeyring
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict
from sqlalchemy import text

from cve_automation.inventory_adapter import encode, normalize, validate


class Settings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_ANSIBLE_")
    service_name: str = "cve-automation"
    keyring_file: Path
    work_directory: Path


class Request(Payload):
    run_id: UUID


class Result(Payload):
    success: bool


async def one(session: Any, sql: str, **params: Any) -> dict[str, Any] | None:
    row = (await session.execute(text(sql), params)).mappings().first()
    return dict(row) if row else None


def destination(host: str, port: int) -> str:
    """Resolve a configured SSH target without network allowlists or address exclusions."""
    addresses = sorted({r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError("ssh_unreachable")
    return str(addresses[0])


class Service:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.settings = database, settings

    def registry(self) -> Registry:
        r = Registry()
        r.register(JobDefinition("inventory.ansible", 1, Request, Result, self.handle, 2400, 3))
        return r

    async def profile(self, run: UUID) -> dict[str, Any] | None:
        async with transaction(self.database) as s:
            return await one(
                s,
                "SELECT p.*,r.id AS run_id,r.action,r.job_id FROM inventory.ansible_profiles p "
                "JOIN inventory.ansible_runs r ON r.server_id=p.server_id AND r.pr"
                "ofile_version=p.version "
                "JOIN inventory.servers server ON server.id=p.server_id WHERE r.id"
                "=:id AND server.status='active' "
                "AND inventory.ansible_owner_active(p.owner_id)",
                id=run,
            )

    async def handle(self, ctx: ExecutionContext, payload: BaseModel) -> Result:
        req = Request.model_validate(payload.model_dump())
        profile = await self.profile(req.run_id)
        if not profile:
            return await self.finish(ctx, req, False, "profile_unavailable")
        try:
            address = await asyncio.to_thread(
                destination,
                profile["host"],
                profile["port"],
            )
            credentials = SSHKeyring(self.settings.keyring_file).decrypt(
                profile["server_id"],
                profile["version"],
                profile["key_id"],
                bytes(profile["ciphertext"]),
            )
        except Exception:
            return await self.finish(ctx, req, False, "destination_or_credentials_unavailable")
        async with transaction(self.database) as s:
            await s.execute(
                text("SELECT inventory.ansible_run_update(:id,'running')"), {"id": req.run_id}
            )
        self.settings.work_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(
            prefix=f"ansible-{req.run_id}-", dir=self.settings.work_directory
        ) as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            plan = {
                k: profile[k]
                for k in [
                    "port",
                    "username",
                    "use_sudo",
                    "auth_method",
                    "action",
                    "host_key",
                    "mount_paths",
                ]
            }
            plan.update(
                {
                    "address": address,
                    "credentials": credentials,
                }
            )
            path = root / "plan.json"
            path.write_text(json.dumps(plan))
            path.chmod(0o600)
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "cve_automation.execute",
                str(path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                while process.returncode is None:
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(process.wait(), 2)
                    current = await self.profile(req.run_id)
                    if (
                        ctx.stopping.is_set()
                        or not current
                        or current["version"] != profile["version"]
                    ):
                        raise LeaseLost()
                    async with transaction(self.database) as s:
                        valid = (
                            await s.execute(
                                text(
                                    "SELECT automation.check_job_fence(:id,:worker,:token,:epoch)"
                                ),
                                ctx.repository.fence(ctx.job),
                            )
                        ).scalar_one()
                        if valid is False:
                            raise LeaseLost()
                output = root / "result.json"
                if not output.exists():
                    return await self.finish(ctx, req, False, "execution_failed")
                result = json.loads(output.read_text())
                if not result["success"]:
                    return await self.finish(ctx, req, False, result["error_code"])
                document = None
                if profile["action"] == "collect":
                    document = normalize(json.loads((root / "inventory-input.json").read_text()))
                return await self.finish(ctx, req, True, None, result.get("host_key"), document)
            finally:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 5)
                    except TimeoutError:
                        os.killpg(process.pid, signal.SIGKILL)
                        await process.wait()

    async def finish(
        self,
        ctx: ExecutionContext,
        req: Request,
        success: bool,
        error: str | None = None,
        host_key: str | None = None,
        document: dict[str, Any] | None = None,
    ) -> Result:
        async def commit(s: Any) -> Result:
            submission = None
            if document is not None:
                profile = await self.profile(req.run_id)
                if not profile:
                    raise LeaseLost()
                validate(document)
                await s.execute(
                    text(
                        "SELECT inventory.resolve_upload_host(CAST(:host AS jsonb),:actor,"
                        ":server,NULL)"
                    ),
                    {
                        "host": json.dumps(document["host"]),
                        "actor": profile["owner_id"],
                        "server": profile["server_id"],
                    },
                )
                raw = encode(document)
                canonical = hashlib.sha256(raw).digest()
                iid = UUID(document["inventory_id"])
                await s.execute(
                    text(
                        "INSERT INTO inventory.submission_identities VALUES(:iid,:server,:"
                        "hash) ON CONFLICT DO NOTHING"
                    ),
                    {"iid": iid, "server": profile["server_id"], "hash": canonical},
                )
                row = await one(
                    s,
                    "INSERT INTO inventory.submissions(inventory_id,server_id,source,s"
                    "ource_identity,actor_user_id,"
                    "schema_version,collected_at,payload_json,payload_raw,payload_sha2"
                    "56,canonical_sha256,idempotency_key,correlation_id,ansible_run_id"
                    ") "
                    "VALUES(:iid,:server,'managed_ansible',:run,:owner,'1.3',:captured"
                    ",CAST(:doc AS jsonb),:raw,:hash,:hash,:key,:corr,:run) RETURNING "
                    "id",
                    iid=iid,
                    server=profile["server_id"],
                    run=req.run_id,
                    owner=profile["owner_id"],
                    captured=__import__("datetime").datetime.fromisoformat(document["captured_at"]),
                    doc=raw.decode(),
                    raw=raw,
                    hash=canonical,
                    key="ansible:" + str(req.run_id),
                    corr=ctx.job.correlation_id,
                )
                assert row
                submission = row["id"]
            state = "succeeded" if success else "failed"
            await s.execute(
                text("SELECT inventory.ansible_run_update(:id,:state,:error,:key,:submission)"),
                {
                    "id": req.run_id,
                    "state": state,
                    "error": error,
                    "key": host_key,
                    "submission": submission,
                },
            )
            return Result(success=success)

        if success:
            result = await ctx.complete(commit)
            assert isinstance(result, Result)
            return result
        retry = error in {"ssh_unreachable", "execution_failed"}
        async with transaction(self.database) as session:
            result = await commit(session)
            if not await ctx.repository.finish_in(
                session,
                ctx.job,
                "retry" if retry else "failed",
                ErrorCode.NETWORK if retry else ErrorCode.PERMANENT,
            ):
                raise LeaseLost()
        ctx.completed = True
        return result
