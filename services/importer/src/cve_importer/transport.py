"""Direct verified HTTPS streaming, source/path allowlists, private bounded transfer cache."""

import asyncio
import contextlib
import hashlib
import json
import os
import ssl
import stat
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from uuid import UUID, uuid4

import httpx
from cve_common.config.secrets import read_secret
from cve_common.http.client import ServiceClient
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.logging.redaction import register_secret

from cve_importer.contracts import Configuration, ImportFailure, Source

HOSTS: dict[str, set[str]] = {
    "cve_list": {
        "api.github.com",
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    },
    "nvd": {"services.nvd.nist.gov"},
    "cisa_kev": {"www.cisa.gov"},
    "ubuntu": {"ubuntu.com"},
    "osv": {"storage.googleapis.com"},
}


def allowed(source: str, url: str, *, redirect: bool = False) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        path = unquote(parsed.path)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.port not in (None, 443)
            or host not in HOSTS.get(source, set())
            or any(c in url for c in "\r\n\0\\")
            or ".." in path.split("/")
        ):
            raise ImportFailure("source_url_forbidden")
        prefixes = {
            "api.github.com": "/repos/CVEProject/cvelistV5/releases",
            "github.com": "/CVEProject/cvelistV5/releases/download/",
            "release-assets.githubusercontent.com": "/github-production-release-asset/",
            "objects.githubusercontent.com": "/github-production-release-asset-",
            "services.nvd.nist.gov": "/rest/json/cves/2.0",
            "www.cisa.gov": "/sites/default/files/feeds/known_exploited_vulnerabilities",
            "ubuntu.com": "/security/",
            "storage.googleapis.com": "/osv-vulnerabilities/",
        }
        exact = {
            "api.github.com": {"/repos/CVEProject/cvelistV5/releases"},
            "services.nvd.nist.gov": {"/rest/json/cves/2.0"},
            "www.cisa.gov": {"/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
            "ubuntu.com": {"/security/cves.json", "/security/notices.json"},
        }
        if host in exact and path not in exact[host]:
            raise ImportFailure("source_path_forbidden")
        if not path.startswith(prefixes[str(host)]) or (
            host in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
            and not redirect
        ):
            raise ImportFailure("source_path_forbidden")
        return url
    except (ValueError, KeyError):
        raise ImportFailure("source_url_forbidden") from None


@dataclass(frozen=True)
class Artifact:
    path: Path
    location: str
    sha256: bytes
    size: int
    milliseconds: float
    content_type: str

    def metadata(self) -> dict[str, str | int | float]:
        return {"content_type": self.content_type}


def private(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in (0o600, 0o400)
            ):
                raise ImportFailure("unsafe_cache_file")
            return handle.read(8193)
    except OSError:
        raise ImportFailure("unsafe_cache_file") from None


class Transport:
    def __init__(
        self,
        configuration: Configuration,
        scratch: Path,
        *,
        nvd_key_file: Path | None = None,
        ca_file: Path | None = None,
        reserve: Callable[[str, float], Awaitable[float]] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.configuration = configuration
        self.ca_file = ca_file
        self.scratch = scratch
        secret = read_secret(nvd_key_file) if nvd_key_file else None
        self.key = secret.get_secret_value() if secret else None
        if secret:
            register_secret(secret)
        self.base = ServiceClient(
            {"source": "https://services.nvd.nist.gov"},
            external=True,
            timeout=30,
            ca_file=str(ca_file) if ca_file else None,
        )
        self.client = client or self.base.client
        self.reserve = reserve
        self.previous: dict[str, float] = {}
        self.rate_limited = 0
        self.transfer_lock = asyncio.Lock()

    async def close(self) -> None:
        if self.client is not self.base.client:
            await self.client.aclose()
        await self.base.close()

    def directory(self, run_id: UUID) -> Path:
        if self.scratch.is_symlink():
            raise ImportFailure("unsafe_cache_directory")
        self.scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = self.scratch.stat()
        if root.st_uid != os.getuid() or stat.S_IMODE(root.st_mode) != 0o700:
            raise ImportFailure("unsafe_cache_directory")
        directory = self.scratch / str(run_id)
        if directory.is_symlink():
            raise ImportFailure("unsafe_cache_directory")
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ImportFailure("unsafe_cache_directory")
        return directory

    async def pace(self, source: str) -> None:
        interval = self.configuration.minimum_delay
        if source == "nvd":
            interval = max(self.configuration.nvd_delay, 0.65 if self.key else 6.1)
        wait = (
            await self.reserve(source, max(0.1, interval))
            if self.reserve
            else self.previous.get(source, 0) + interval - time.monotonic()
        )
        if wait > 0:
            await asyncio.sleep(wait)
        self.previous[source] = time.monotonic()

    def secret_check(self, raw: bytes | str) -> None:
        value = raw.encode() if isinstance(raw, str) else raw
        if self.key and self.key.encode() in value:
            raise ImportFailure("credential_in_source")

    def usage(self) -> int:
        total = 0
        for directory in self.scratch.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                raise ImportFailure("unsafe_cache_directory")
            # The persistent Git working tree is managed by GitSource, separately
            # from the bounded HTTP download cache. Never traverse it as artifacts.
            if directory.name == "git":
                info = directory.stat()
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ImportFailure("unsafe_cache_directory")
                continue
            for path in directory.iterdir():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ImportFailure("unsafe_cache_file")
                total += info.st_size
                if total > self.configuration.scratch_limit:
                    raise ImportFailure("scratch_quota")
        return total

    async def fetch(self, source: Source, url: str, run_id: UUID, **arguments: object) -> Artifact:
        async with self.transfer_lock:
            return await self._fetch(source, url, run_id, **arguments)  # type: ignore[arg-type]

    async def _fetch(
        self,
        source: Source,
        url: str,
        run_id: UUID,
        *,
        expected: str | None = None,
        kind: str = "json",
        cache: bool = True,
    ) -> Artifact:
        allowed(source, url)
        directory = self.directory(run_id)
        usage = self.usage()
        filename = hashlib.sha256(url.encode()).hexdigest()
        target = directory / (filename + ".bin")
        metadata = directory / (filename + ".json")
        if cache and target.exists() and metadata.exists():
            info = json.loads(private(metadata))
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                status = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_uid != os.getuid()
                    or stat.S_IMODE(status.st_mode) != 0o600
                    or status.st_size > self.configuration.max_download
                ):
                    raise ImportFailure("unsafe_cache_file")
                cached_digest = hashlib.file_digest(handle, "sha256").digest()
            if cached_digest.hex() != info["sha256"] or (
                expected and cached_digest.hex() != expected.removeprefix("sha256:")
            ):
                raise ImportFailure("artifact_hash_mismatch")
            return Artifact(target, url, cached_digest, status.st_size, 0, info["content_type"])
        for attempt in range(self.configuration.request_attempts):
            temporary = directory / (filename + "." + uuid4().hex + ".part")
            started = time.monotonic()
            delay = min(2**attempt, self.configuration.max_retry_delay)
            try:
                current = url
                async with asyncio.timeout(self.configuration.download_seconds):
                    for hop in range(4):
                        allowed(source, current, redirect=hop > 0)
                        await self.pace(source)
                        headers = {
                            "Accept-Encoding": "identity",
                            "User-Agent": "cve-importer/0.15.0",
                            "Accept": (
                                "application/json,application/zip,text/plain,"
                                "text/csv,application/octet-stream"
                            ),
                        }
                        if (
                            self.key
                            and source == "nvd"
                            and urlsplit(current).hostname == "services.nvd.nist.gov"
                        ):
                            headers["apiKey"] = self.key
                        self.client.cookies.clear()
                        async with self.client.stream(
                            "GET", current, headers=headers, follow_redirects=False
                        ) as response:
                            if response.status_code in {301, 302, 303, 307, 308}:
                                if hop == 3 or "location" not in response.headers:
                                    raise ImportFailure("redirect_limit")
                                current = urljoin(current, response.headers["location"])
                                continue
                            if response.status_code == 429 or response.status_code in {
                                500,
                                502,
                                503,
                                504,
                            }:
                                self.rate_limited += int(response.status_code == 429)
                                retry = response.headers.get("Retry-After")
                                if retry:
                                    with contextlib.suppress(ValueError, TypeError):
                                        delay = (
                                            float(retry)
                                            if retry.isascii() and retry.isdigit()
                                            else max(
                                                0,
                                                (
                                                    parsedate_to_datetime(retry) - datetime.now(UTC)
                                                ).total_seconds(),
                                            )
                                        )
                                    if delay > self.configuration.max_retry_delay:
                                        raise ImportFailure("retry_after_exceeds_budget")
                                raise JobError(
                                    ErrorCode.RATE_LIMIT
                                    if response.status_code == 429
                                    else ErrorCode.UNAVAILABLE
                                )
                            if response.status_code != 200:
                                raise ImportFailure("http_permanent")
                            encoding = response.headers.get("content-encoding", "identity")
                            if encoding not in {"", "identity"}:
                                raise ImportFailure("content_encoding_forbidden")
                            content_type = (
                                response.headers.get("content-type", "").split(";", 1)[0].lower()
                            )
                            accepted = (
                                {"application/zip", "application/octet-stream"}
                                if kind == "zip"
                                else {
                                    "application/json",
                                    "application/vnd.github+json",
                                    "text/plain",
                                    "text/csv",
                                    "application/octet-stream",
                                }
                            )
                            if content_type not in accepted:
                                raise ImportFailure("source_content_type")
                            length = response.headers.get("content-length")
                            maximum = (
                                self.configuration.max_download
                                if kind in {"zip", "csv"}
                                else self.configuration.max_json
                            )
                            if length and (not length.isdigit() or int(length) > maximum):
                                raise ImportFailure("download_size")
                            digest = hashlib.sha256()
                            count = 0
                            tail = b""
                            fd = os.open(
                                temporary,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600,
                            )
                            with os.fdopen(fd, "wb") as handle:
                                async for chunk in response.aiter_raw(262144):
                                    count += len(chunk)
                                    if usage + count + 8192 > self.configuration.scratch_limit:
                                        raise ImportFailure("scratch_quota")
                                    if count > maximum:
                                        raise ImportFailure("download_size")
                                    self.secret_check(tail + chunk)
                                    tail = (tail + chunk)[-4096:]
                                    digest.update(chunk)
                                    handle.write(chunk)
                                handle.flush()
                                os.fsync(handle.fileno())
                            if length and count != int(length):
                                raise JobError(ErrorCode.NETWORK)
                            if expected and digest.hexdigest() != expected.removeprefix("sha256:"):
                                raise ImportFailure("artifact_hash_mismatch")
                            if target.is_symlink() or metadata.is_symlink():
                                raise ImportFailure("unsafe_cache_file")
                            os.replace(temporary, target)
                            metadata.write_text(
                                json.dumps(
                                    {"sha256": digest.hexdigest(), "content_type": content_type}
                                )
                            )
                            metadata.chmod(0o600)
                            return Artifact(
                                target,
                                url,
                                digest.digest(),
                                count,
                                (time.monotonic() - started) * 1000,
                                content_type,
                            )
                    raise ImportFailure("redirect_limit")
            except (
                httpx.TimeoutException,
                httpx.NetworkError,
                httpx.ProxyError,
                httpx.RemoteProtocolError,
                TimeoutError,
                JobError,
            ) as error:
                if isinstance(error, httpx.ConnectError) and isinstance(
                    error.__cause__, ssl.SSLError
                ):
                    raise ImportFailure("source_tls") from None
                if attempt + 1 == self.configuration.request_attempts:
                    if isinstance(error, JobError):
                        raise
                    raise JobError(ErrorCode.NETWORK) from None
                await asyncio.sleep(delay)
            finally:
                temporary.unlink(missing_ok=True)
        raise JobError(ErrorCode.UNAVAILABLE)
