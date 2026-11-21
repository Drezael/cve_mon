"""Verified FIRST daily gzip/CSV, isolated parsing and complete-dataset activation."""

import asyncio
import csv
import gzip
import hashlib
import multiprocessing
import os
import re
import resource
import ssl
import stat
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import UUID, uuid4

import httpx
from cve_common.http.client import ServiceClient
from cve_common.jobs.errors import ErrorCode, JobError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_enricher.contracts import Configuration, EnrichmentError, Event, Result
from cve_enricher.normalize import CVE
from cve_enricher.repository import emit

HOST = "epss.empiricalsecurity.com"


def allowed(url: str) -> str:
    p = urlsplit(url)
    if (
        p.scheme != "https"
        or p.hostname != HOST
        or p.port not in (None, 443)
        or p.username
        or p.password
        or p.query
        or p.fragment
        or not re.fullmatch(
            r"/epss_scores-(?:current|[0-9]{4}-[0-9]{2}-[0-9]{2})[.]csv[.]gz", p.path
        )
    ):
        raise EnrichmentError("epss_url_forbidden")
    return url


class Client:
    def __init__(
        self,
        cfg: Configuration,
        scratch: Path,
        ca_file: Path | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.cfg, self.scratch = cfg, scratch
        self.base = ServiceClient(
            {"epss": "https://" + HOST},
            external=True,
            ca_file=str(ca_file) if ca_file else None,
            timeout=30,
        )
        self.client = client or self.base.client

    async def close(self) -> None:
        if self.client is not self.base.client:
            await self.client.aclose()
        await self.base.close()

    async def download(self, day: date | None) -> tuple[Path, str, str]:
        if day is not None and day > datetime.now(UTC).date():
            raise EnrichmentError("epss_future_date")
        self.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            self.scratch.is_symlink()
            or self.scratch.stat().st_uid != os.getuid()
            or stat.S_IMODE(self.scratch.stat().st_mode) != 0o700
        ):
            raise EnrichmentError("epss_unsafe_scratch")
        # A single global EPSS lease prevents concurrent downloads and scratch accumulation.
        path = self.scratch / (str(uuid4()) + ".csv.gz")
        url = allowed(
            "https://"
            + HOST
            + "/epss_scores-"
            + (day.isoformat() if day else "current")
            + ".csv.gz"
        )
        for attempt in range(3):
            retry_delay = float(2**attempt)
            try:
                current = url
                async with asyncio.timeout(self.cfg.epss_timeout):
                    for _hop in range(3):
                        allowed(current)
                        self.client.cookies.clear()
                        async with self.client.stream(
                            "GET",
                            current,
                            follow_redirects=False,
                            headers={
                                "Accept-Encoding": "identity",
                                "Accept": "application/gzip,application/octet-stream",
                                "User-Agent": "cve-enricher/0.16.0",
                            },
                        ) as response:
                            if response.status_code in {301, 302, 303, 307, 308}:
                                current = allowed(
                                    urljoin(current, response.headers.get("location", ""))
                                )
                                continue
                            if response.status_code in {429, 500, 502, 503, 504}:
                                retry = response.headers.get("Retry-After")
                                if retry:
                                    try:
                                        retry_delay = (
                                            float(retry)
                                            if retry.isdigit()
                                            else max(
                                                0,
                                                (
                                                    parsedate_to_datetime(retry) - datetime.now(UTC)
                                                ).total_seconds(),
                                            )
                                        )
                                    except (ValueError, TypeError):
                                        retry_delay = float(2**attempt)
                                    if retry_delay > 120:
                                        raise EnrichmentError("epss_retry_after_budget")
                                raise JobError(
                                    ErrorCode.RATE_LIMIT
                                    if response.status_code == 429
                                    else ErrorCode.UNAVAILABLE
                                )
                            if response.status_code != 200:
                                raise EnrichmentError("epss_http_permanent")
                            if response.headers.get("content-encoding", "identity") not in (
                                "",
                                "identity",
                            ):
                                raise EnrichmentError("epss_content_encoding")
                            if response.headers.get("content-type", "").split(";", 1)[0] not in {
                                "application/gzip",
                                "application/x-gzip",
                                "application/octet-stream",
                                "binary/octet-stream",
                            }:
                                raise EnrichmentError("epss_content_type")
                            length = response.headers.get("content-length")
                            if length and (
                                not length.isdigit() or int(length) > self.cfg.epss_max_download
                            ):
                                raise EnrichmentError("epss_download_limit")
                            count = 0
                            sha = hashlib.sha256()
                            fd = os.open(
                                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                            )
                            with os.fdopen(fd, "wb") as handle:
                                async for chunk in response.aiter_raw(262144):
                                    count += len(chunk)
                                    if count > self.cfg.epss_max_download:
                                        raise EnrichmentError("epss_download_limit")
                                    sha.update(chunk)
                                    handle.write(chunk)
                                handle.flush()
                                os.fsync(handle.fileno())
                            if length and int(length) != count:
                                raise JobError(ErrorCode.NETWORK)
                            return path, sha.hexdigest(), current
                    raise EnrichmentError("epss_redirect_limit")
            except (httpx.HTTPError, JobError, TimeoutError) as error:
                path.unlink(missing_ok=True)
                cause: BaseException | None = error
                for _ in range(8):
                    if isinstance(cause, ssl.SSLError):
                        raise EnrichmentError("epss_tls") from None
                    cause = cause.__cause__ if cause else None
                if attempt == 2:
                    raise JobError(ErrorCode.NETWORK) from None
                await asyncio.sleep(retry_delay)
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        raise JobError(ErrorCode.NETWORK)


def parse_worker(
    pipe: Connection, path: str, cfg_value: dict[str, Any], requested: str | None
) -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (536870912,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cfg = Configuration.model_validate(cfg_value)
        csv.field_size_limit(1024)
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            meta = handle.readline(1025)
            match = re.fullmatch(
                r"#model_version:(v[0-9]{4}\.[0-9]{2}\.[0-9]{2}),score_date:([^,\r\n]+)\r?\n", meta
            )
            if not match:
                raise EnrichmentError("epss_metadata")
            model, stamp = match.groups()
            day = datetime.fromisoformat(stamp.replace("Z", "+00:00")).date()
            if requested and day.isoformat() != requested or day > datetime.now(UTC).date():
                raise EnrichmentError("epss_date_mismatch")
            if handle.readline(1025).strip() != "cve,epss,percentile":
                raise EnrichmentError("epss_header")
            pipe.send((True, {"date": day.isoformat(), "model": model}, False))
            if pipe.recv() != "next":
                return
            seen: set[str] = set()
            rows = []
            size = len(meta) + 20
            for row in csv.reader(handle):
                size += sum(len(v) for v in row) + 3
                if (
                    size > cfg.epss_max_unpacked
                    or len(row) != 3
                    or len(seen) >= cfg.epss_max_rows
                    or any(not value.isascii() for value in row)
                ):
                    raise EnrichmentError("epss_size_or_columns")
                if not CVE.fullmatch(row[0]) or row[0] in seen:
                    raise EnrichmentError("epss_identity_duplicate")
                score, percentile = Decimal(row[1]), Decimal(row[2])
                if any(
                    not v.is_finite()
                    or not 0 <= v <= 1
                    or isinstance(v.as_tuple().exponent, int)
                    and int(v.as_tuple().exponent) < -18
                    for v in (score, percentile)
                ):
                    raise EnrichmentError("epss_range")
                seen.add(row[0])
                rows.append({"cve": row[0], "score": str(score), "percentile": str(percentile)})
                if len(rows) >= cfg.epss_batch_size:
                    pipe.send((True, {"rows": rows}, False))
                    if pipe.recv() != "next":
                        return
                    rows = []
            if len(seen) < cfg.epss_min_rows:
                raise EnrichmentError("epss_too_few_rows")
            pipe.send((True, {"rows": rows, "count": len(seen)}, True))
    except EnrichmentError as error:
        pipe.send((False, str(error), True))
    except (OSError, EOFError, ValueError, InvalidOperation, csv.Error):
        pipe.send((False, "epss_invalid_gzip_csv", True))
    except Exception:
        pipe.send((False, "epss_parser_failure", True))
    finally:
        pipe.close()


async def stream(path: Path, cfg: Configuration, requested: date | None) -> Any:
    ctx = multiprocessing.get_context("spawn")
    parent, writer = ctx.Pipe()
    process = ctx.Process(
        target=parse_worker,
        args=(writer, str(path), cfg.model_dump(), requested.isoformat() if requested else None),
        daemon=True,
    )
    process.start()
    writer.close()
    try:
        while True:
            async with asyncio.timeout(60):
                ok, value, done = await asyncio.to_thread(parent.recv)
            if not ok:
                raise EnrichmentError(value)
            yield value, done
            if done:
                break
            parent.send("next")
    except (EOFError, OSError, TimeoutError):
        raise EnrichmentError("epss_parser_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()


async def activate(
    session: AsyncSession, dataset: UUID, count: int, correlation: UUID, cfg: Configuration
) -> Result:
    row = (
        (
            await session.execute(
                text("SELECT * FROM cve.epss_import_runs WHERE id=:id FOR UPDATE"), {"id": dataset}
            )
        )
        .mappings()
        .one()
    )
    old = (
        (
            await session.execute(
                text(
                    "SELECT r.* FROM cve.epss_current_dataset h JOIN "
                    "cve.epss_import_runs r ON r.id=h.dataset_id"
                )
            )
        )
        .mappings()
        .first()
    )
    if old and count < old["row_count"] * cfg.epss_min_fraction:
        raise EnrichmentError("epss_count_regression")
    if row["status"] != "completed":
        await session.execute(
            text(
                "UPDATE cve.epss_import_runs SET "
                "status='completed',row_count=:count,completed_at=clock_timestamp("
                ") WHERE id=:id"
            ),
            {"id": dataset, "count": count},
        )
    changed = not old or old["id"] != dataset and row["score_date"] >= old["score_date"]
    if changed:
        version = (
            await session.execute(
                text(
                    "INSERT INTO "
                    "cve.epss_current_dataset(singleton,dataset_id) "
                    "VALUES(true,:id) ON CONFLICT(singleton) DO UPDATE "
                    "SET "
                    "dataset_id=excluded.dataset_id,current_version=cve.e"
                    "pss_current_dataset.current_version+1 RETURNING "
                    "current_version"
                ),
                {"id": dataset},
            )
        ).scalar_one()
        await emit(
            session,
            "epss_updated",
            str(dataset) + ":activated:" + str(version),
            correlation,
            Event(dataset_id=dataset, current_version=version, changes=["epss"]),
        )
    return Result(dataset_id=dataset, changed=bool(changed), count=count)
