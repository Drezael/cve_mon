"""Fixed CVEProject Git origin, pinned commit manifests and restartable incremental pages."""

import asyncio
import fcntl
import hashlib
import json
import multiprocessing
import os
import re
import resource
import stat
import time
from concurrent.futures import ProcessPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO
from uuid import UUID

if TYPE_CHECKING:
    from cve_importer.adapters import Page

from cve_common.jobs.errors import ErrorCode, JobError

from cve_importer.contracts import Configuration, ImportFailure
from cve_importer.transport import Artifact, Transport
from cve_importer.validation import canonical, decode, record

REMOTE = "https://github.com/CVEProject/cvelistV5.git"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
PATH = re.compile(r"^cves/([0-9]{4})/[0-9]+xxx/(CVE-\1-[0-9]{4,})\.json$")


def worker_limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (1073741824,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (3000, 3000))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def validate_items(
    repository: Path, items: list[dict[str, Any]], maximum: int
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    records, errors, removed = [], [], []
    for item in items:
        if item["removed"]:
            removed.append(item["identity"])
            continue
        try:
            path = repository / item["path"]
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise ImportFailure("git_nonregular_record")
                raw = handle.read(maximum + 1)
            if (
                hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                != item["oid"]
            ):
                raise ImportFailure("git_worktree_changed")
            result = record("cve_list", decode(raw, maximum))
            if result["external_id"] != item["identity"]:
                raise ImportFailure("git_identity_mismatch")
            records.append({**result, "position": item["path"], "git_blob_oid": item["oid"]})
        except ImportFailure as error:
            errors.append({"position": item["path"], "code": str(error)})
        except OSError:
            raise ImportFailure("git_worktree_changed") from None
    return records, errors, removed


class GitSource:
    def __init__(self, transport: Transport, run: UUID, cfg: Configuration) -> None:
        self.transport, self.run, self.cfg = transport, run, cfg
        self.root = transport.scratch / "git"
        self.repository = self.root / "cvelistV5"
        self.lock: int | None = None
        self.manifest: BinaryIO | None = None
        self.pool: ProcessPoolExecutor | None = None
        self.offset = 0

    def prefix(self) -> list[str]:
        args = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "credential.helper=",
            "-c",
            "http.proxy=",
            "-c",
            "http.sslVerify=true",
            "-c",
            "http.version=HTTP/1.1",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "pack.threads=2",
        ]
        if self.transport.ca_file:
            args.extend(["-c", "http.sslCAInfo=" + str(self.transport.ca_file)])
        return args

    def environment(self) -> dict[str, str]:
        return {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }

    async def git(self, *args: str, root: Path | None = None, maximum: int = 268435456) -> bytes:
        process = await asyncio.create_subprocess_exec(
            *self.prefix(),
            *args,
            cwd=root,
            env=self.environment(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        async def diagnostics() -> bytes:
            captured = bytearray()
            assert process.stderr is not None
            while block := await process.stderr.read(4096):
                captured.extend(block[: max(0, 8192 - len(captured))])
            return bytes(captured).lower()

        stderr = asyncio.create_task(diagnostics())
        chunks, size = [], 0
        try:
            async with asyncio.timeout(self.cfg.download_seconds):
                assert process.stdout is not None
                while chunk := await process.stdout.read(65536):
                    size += len(chunk)
                    if size > maximum:
                        raise ImportFailure("git_output_limit")
                    chunks.append(chunk)
                if await process.wait():
                    detail = await stderr
                    code = "GIT_COMMAND_FAILED"
                    for marker, diagnostic in (
                        (b"could not resolve", "GIT_DNS_FAILED"),
                        (b"ssl certificate", "GIT_TLS_FAILED"),
                        (b"http/2", "GIT_HTTP2_FAILED"),
                        (b"couldn't connect", "GIT_CONNECT_FAILED"),
                        (b"connection reset", "GIT_CONNECTION_RESET"),
                        (b"timed out", "GIT_REMOTE_TIMEOUT"),
                    ):
                        if marker in detail:
                            code = diagnostic
                            break
                    raise JobError(ErrorCode.NETWORK, diagnostic_code=code)
            return b"".join(chunks)
        finally:
            if process.returncode is None:
                # Git HTTPS helpers belong to this process group too.
                import signal

                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
            await asyncio.gather(stderr, return_exceptions=True)

    async def acquire(self) -> None:
        self.transport.directory(self.run)
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_uid != os.getuid():
            raise ImportFailure("unsafe_git_cache")
        self.lock = os.open(
            self.root / "repository.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock)
            self.lock = None
            raise JobError(ErrorCode.TEMPORARY, diagnostic_code="GIT_CACHE_BUSY") from None

    async def plan(self, previous: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        if self.lock is None:
            await self.acquire()
        if self.repository.is_symlink():
            raise ImportFailure("unsafe_git_cache")
        if self.repository.exists():
            git_directory = self.repository / ".git"
            if git_directory.is_symlink() or not git_directory.is_dir():
                raise ImportFailure("unsafe_git_cache")
            # Only this importer owns the private cache. The flock excludes live Git commands.
            stale = list(git_directory.rglob("*.lock"))
            for lock in stale:
                if lock.is_symlink() or not lock.is_file():
                    raise ImportFailure("unsafe_git_cache")
                lock.unlink()
            if stale:
                await self.git("reset", "--hard", "HEAD", root=self.repository)
        if not self.repository.exists():
            temporary = self.root / "clone-in-progress"
            if temporary.exists():
                import shutil

                shutil.rmtree(temporary)
            await self.git(
                "clone",
                "--depth=1",
                "--no-tags",
                "--single-branch",
                "--branch",
                "main",
                "--",
                REMOTE,
                str(temporary),
            )
            temporary.rename(self.repository)
        else:
            remote = (
                (await self.git("remote", "get-url", "origin", root=self.repository))
                .decode()
                .strip()
            )
            if remote != REMOTE:
                raise ImportFailure("git_origin_changed")
            await self.git(
                "pull",
                "--ff-only",
                "--no-rebase",
                "--no-tags",
                "origin",
                "main",
                root=self.repository,
            )
        head = (await self.git("rev-parse", "HEAD", root=self.repository)).decode().strip()
        base = previous.get("git_commit")
        if not COMMIT.fullmatch(head) or (base is not None and not COMMIT.fullmatch(base)):
            raise ImportFailure("invalid_git_commit")
        if base:
            try:
                await self.git("cat-file", "-e", base + "^{commit}", root=self.repository)
            except JobError:
                await self.git(
                    "fetch", "--depth=1", "--no-tags", "origin", base, root=self.repository
                )
            raw = await self.git(
                "diff",
                "--raw",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--abbrev=40",
                "-z",
                base,
                head,
                "--",
                "cves",
                root=self.repository,
            )
            tokens = raw.split(b"\0")
            candidates = []
            for offset in range(0, len(tokens) - 1, 2):
                metadata, path = tokens[offset].decode().split(), tokens[offset + 1].decode()
                mode, oid, status_code = metadata[1], metadata[3], metadata[4]
                candidates.append((path, oid, mode, status_code == "D"))
        else:
            raw = await self.git("ls-tree", "-r", "-z", head, "--", "cves", root=self.repository)
            candidates = []
            for item in raw.split(b"\0"):
                if item:
                    meta, path = item.decode().split("\t", 1)
                    mode, kind, oid = meta.split()
                    if kind == "blob":
                        candidates.append((path, oid, mode, False))
        # A completed scan with validation failures keeps its unsuccessful paths for retry.
        # Valid unchanged records are already durable and do not require another full scan.
        retry = sorted(
            {path for path in previous.get("git_retry_paths", []) if PATH.fullmatch(path)}
            - {path for path, _, _, _ in candidates}
        )
        for offset in range(0, len(retry), 256):
            selected = retry[offset : offset + 256]
            raw_retry = await self.git(
                "ls-tree", "-r", "-z", head, "--", *selected, root=self.repository
            )
            found = set()
            for item in raw_retry.split(b"\0"):
                if item:
                    meta, path = item.decode().split("\t", 1)
                    mode, kind, oid = meta.split()
                    if kind == "blob" and path in selected:
                        candidates.append((path, oid, mode, False))
                        found.add(path)
            candidates.extend(
                (path, "0" * 40, "000000", True) for path in selected if path not in found
            )
        # A Git rename is represented as D+A. Keep a retained identity present even if
        # its old and new paths land on different import pages.
        retained = {
            match[2]
            for path, _, _, removed in candidates
            if not removed and (match := PATH.fullmatch(path))
        }
        destination = self.transport.directory(self.run) / "git-manifest.jsonl"
        digest, count = hashlib.sha256(), 0
        with destination.open("wb") as output:
            destination.chmod(0o600)
            for path, oid, mode, removed in sorted(candidates):
                match = PATH.fullmatch(path)
                if not match or (removed and match[2] in retained):
                    continue
                if not removed and mode != "100644":
                    raise ImportFailure("git_nonregular_record")
                count += 1
                if count > self.cfg.max_files:
                    raise ImportFailure("git_file_limit")
                line = (
                    canonical({"path": path, "oid": oid, "identity": match[2], "removed": removed})
                    + "\n"
                ).encode()
                output.write(line)
                digest.update(line)
        return {
            "head": head,
            "base": base,
            "count": count,
            "manifest_sha256": digest.hexdigest(),
            "download_ms": (time.monotonic() - started) * 1000,
            "offset": 0,
        }

    def read(self, progress: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
        if self.manifest is None:
            path = self.transport.directory(self.run) / "git-manifest.jsonl"
            if path.is_symlink() or not path.is_file():
                raise ImportFailure("missing_git_manifest")
            # Validate the pinned manifest once on every resume, not once per batch.
            with path.open("rb") as handle:
                if hashlib.file_digest(handle, "sha256").hexdigest() != progress["manifest_sha256"]:
                    raise ImportFailure("git_manifest_changed")
            self.manifest = path.open("rb")
            self.offset = 0
        target = progress["offset"]
        if self.offset > target:
            self.manifest.seek(0)
            self.offset = 0
        while self.offset < target:
            if not self.manifest.readline():
                raise ImportFailure("git_manifest_truncated")
            self.offset += 1
        items = []
        for _ in range(self.cfg.batch_size):
            line = self.manifest.readline()
            if not line:
                break
            items.append(json.loads(line))
            self.offset += 1
        return items, self.offset

    async def page(self, progress: dict[str, Any], previous: dict[str, Any]) -> "Page":
        from cve_importer.adapters import Page

        if self.lock is None:
            await self.acquire()
        if "git" not in progress:
            plan = await self.plan(previous)
            artifact = self.artifact(plan)
            return Page([], [], artifact, {"git": plan}, False)
        plan = progress["git"]
        head = (await self.git("rev-parse", "HEAD", root=self.repository)).decode().strip()
        if head != plan["head"]:
            raise ImportFailure("git_worktree_changed")
        started = time.monotonic()
        items, offset = await asyncio.to_thread(self.read, plan)
        if self.pool is None:
            self.pool = ProcessPoolExecutor(
                max_workers=self.cfg.git_validation_workers,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=worker_limits,
                max_tasks_per_child=128,
            )
        chunk = max(
            1, (len(items) + self.cfg.git_validation_workers - 1) // self.cfg.git_validation_workers
        )
        batches = await asyncio.gather(
            *(
                asyncio.get_running_loop().run_in_executor(
                    self.pool,
                    validate_items,
                    self.repository,
                    items[i : i + chunk],
                    self.cfg.max_json,
                )
                for i in range(0, len(items), chunk)
            )
        )
        records = [r for batch in batches for r in batch[0]]
        errors = [e for batch in batches for e in batch[1]]
        removed = [identity for batch in batches for identity in batch[2]]
        following = {**plan, "offset": offset}
        done = offset == plan["count"]
        if offset > plan["count"] or (not done and offset == plan["offset"]):
            raise ImportFailure("git_manifest_truncated")
        return Page(
            records,
            errors,
            self.artifact(plan),
            {"git": following},
            done,
            {"main": {"git_commit": plan["head"], "transport": "git"}} if done else {},
            (time.monotonic() - started) * 1000,
            removed=removed,
        )

    def artifact(self, plan: dict[str, Any]) -> Artifact:
        return Artifact(
            self.transport.directory(self.run) / "git-manifest.jsonl",
            "https://github.com/CVEProject/cvelistV5/tree/" + plan["head"],
            bytes.fromhex(plan["manifest_sha256"]),
            (self.transport.directory(self.run) / "git-manifest.jsonl").stat().st_size,
            plan["download_ms"],
            "application/x-git-cve-manifest",
        )

    async def close(self) -> None:
        from cve_common.lifecycle.processes import close_pool

        try:
            if self.pool is not None:
                pool, self.pool = self.pool, None
                await close_pool(pool)
        finally:
            if self.manifest:
                self.manifest.close()
                self.manifest = None
            if self.lock is not None:
                fcntl.flock(self.lock, fcntl.LOCK_UN)
                os.close(self.lock)
                self.lock = None
