"""Five independent source protocols; page positions are not successful source cursors."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from cve_importer.contracts import Configuration, ImportFailure, Source
from cve_importer.git_source import GitSource
from cve_importer.transport import Artifact, Transport, allowed
from cve_importer.validation import (
    archive_stream,
    canonical,
    date,
    index_stream,
    isolated,
    record,
)


@dataclass
class Page:
    records: list[dict[str, Any]]
    errors: list[dict[str, str]]
    artifact: Artifact
    progress: dict[str, Any]
    done: bool
    cursors: dict[str, dict[str, Any]] = field(default_factory=dict)
    parse_ms: float = 0
    removed: list[str] = field(default_factory=list)


def pagination(
    value: dict[str, Any],
    key: str,
    offset: int,
    limit: int,
    expected: int | None,
    *,
    nvd: bool = False,
) -> tuple[list[Any], int, bool]:
    entries = value.get(key)
    actual_offset = value.get("startIndex" if nvd else "offset")
    actual_limit = value.get("resultsPerPage" if nvd else "limit")
    total = value.get("totalResults" if nvd else "total_results")
    if (
        not isinstance(entries, list)
        or type(total) is not int
        or total < 0
        or type(actual_offset) is not int
        or actual_offset != offset
        or type(actual_limit) is not int
        or actual_limit < len(entries)
        or actual_limit > limit
    ):
        raise ImportFailure("invalid_pagination")
    if expected is not None and expected != total:
        raise ImportFailure("pagination_changed")
    if len(entries) != min(limit, max(0, total - offset)):
        raise ImportFailure("missing_page")
    return entries, total, offset + len(entries) >= total


def convert(
    source: Source, values: list[Any], *, offset: int = 0
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    result, errors = [], []
    for index, value in enumerate(values):
        try:
            result.append({**record(source, value), "position": str(offset + index)})
        except ImportFailure as error:
            errors.append({"position": str(offset + index), "code": str(error)})
    return result, errors


class Adapters:
    def __init__(
        self,
        source: Source,
        run_id: UUID,
        mode: str,
        configuration: Configuration,
        transport: Transport,
        cursors: dict[str, Any],
        upper: datetime,
    ) -> None:
        self.source, self.run_id, self.mode = source, run_id, mode
        self.configuration, self.transport, self.cursors = configuration, transport, cursors
        self.upper = upper.astimezone(UTC)
        self.archives: dict[str, Any] = {}
        self.archive_files: dict[str, Artifact] = {}
        self.git_source: GitSource | None = None
        self.kev_data: tuple[Artifact, Any, float] | None = None

    async def json(self, url: str, *, cache: bool = True) -> tuple[Artifact, Any, float]:
        artifact = await self.transport.fetch(self.source, url, self.run_id, cache=cache)
        value, elapsed = await isolated("json", artifact.path, self.configuration)
        self.transport.secret_check(canonical(value))
        return artifact, value, elapsed

    async def close(self) -> None:
        if self.git_source is not None:
            await self.git_source.close()
        for iterator in self.archives.values():
            await iterator.aclose()

    async def archive(
        self, url: str, offset: int, *, expected: str | None = None
    ) -> tuple[Artifact, Any, float]:
        if url not in self.archives:
            artifact = await self.transport.fetch(
                self.source, url, self.run_id, kind="zip", expected=expected
            )
            self.archive_files[url] = artifact
            self.archives[url] = archive_stream(
                artifact.path, self.source, offset, self.configuration
            )
        result, elapsed = await anext(self.archives[url])
        return self.archive_files[url], result, elapsed

    async def next(self, progress: dict[str, Any]) -> Page:
        if self.source == "cve_list":
            if self.configuration.cve_list_transport == "git":
                if self.git_source is None:
                    self.git_source = GitSource(self.transport, self.run_id, self.configuration)
                return await self.git_source.page(
                    progress, self.cursors.get("main", {}) if self.mode == "incremental" else {}
                )
            return await self.cveproject(progress)
        if self.source == "nvd":
            return await self.nvd(progress)
        if self.source == "cisa_kev":
            return await self.kev(progress)
        if self.source == "ubuntu":
            return await self.ubuntu(progress)
        return await self.osv(progress)

    async def cveproject(self, progress: dict[str, Any]) -> Page:
        plan = progress.get("plan")
        if plan is None:
            meta, releases, milliseconds = await self.json(
                "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=1"
            )
            if not isinstance(releases, list) or not releases:
                raise ImportFailure("missing_release")
            release = releases[0]
            tag = release.get("tag_name", "")
            match = re.fullmatch(r"cve_(\d{4}-\d{2}-\d{2})_(\d{2})00Z", tag)
            if not match or release.get("draft") or release.get("prerelease"):
                raise ImportFailure("invalid_release")
            day, hour = match.groups()
            assets = release.get("assets", [])
            baseline = next(
                (
                    a
                    for a in assets
                    if re.fullmatch(
                        re.escape(day) + r"_all_CVEs_at_midnight\.zip(?:\.zip)?", a.get("name", "")
                    )
                ),
                None,
            )
            delta = next(
                (a for a in assets if a.get("name") == f"{day}_delta_CVEs_at_{hour}00Z.zip"), None
            )
            previous = self.cursors.get("main", {})
            if not baseline or not delta:
                raise ImportFailure("missing_baseline_or_delta")
            if self.mode == "incremental" and previous.get("baseline_day") != day:
                raise ImportFailure("delta_chain_gap")
            selected = [delta] if self.mode == "incremental" else [baseline, delta]
            plan = {
                "tag": tag,
                "baseline_day": day,
                "assets": [
                    {
                        "location": allowed(self.source, a["browser_download_url"]),
                        "digest": a.get("digest"),
                        "size": a["size"],
                    }
                    for a in selected
                ],
            }
            if self.mode == "incremental" and previous.get("tag") == tag:
                return Page([], [], meta, {"plan": plan}, True, {"main": previous}, milliseconds)
            # Pin the release before downloading a large artifact: a safe zero-record checkpoint.
            return Page(
                [], [], meta, {"plan": plan, "asset": 0, "offset": 0}, False, parse_ms=milliseconds
            )
        index = progress.get("asset", 0)
        asset = plan["assets"][index]
        result: dict[str, Any]
        if asset["size"] == 22 and index == len(plan["assets"]) - 1:
            artifact = await self.transport.fetch(
                self.source,
                asset["location"],
                self.run_id,
                expected=asset.get("digest"),
                kind="zip",
            )
            if artifact.path.read_bytes() != b"PK\x05\x06" + b"\x00" * 18:
                raise ImportFailure("invalid_archive")
            result, milliseconds = {"records": [], "errors": [], "offset": 0, "done": True}, 0.0
        else:
            artifact, result, milliseconds = await self.archive(
                asset["location"], progress.get("offset", 0), expected=asset.get("digest")
            )
        if artifact.size != asset["size"]:
            raise ImportFailure("artifact_size_mismatch")
        next_index = index + int(result["done"])
        done = next_index == len(plan["assets"])
        following = {
            "plan": plan,
            "asset": next_index,
            "offset": 0 if result["done"] else result["offset"],
        }
        cursor = {"main": {"tag": plan["tag"], "baseline_day": plan["baseline_day"]}}
        return Page(
            result["records"], result["errors"], artifact, following, done, cursor, milliseconds
        )

    async def nvd(self, progress: dict[str, Any]) -> Page:
        cfg = self.configuration
        end = self.upper
        if "window_start" not in progress:
            previous = self.cursors.get("main", {}).get("watermark")
            start = (
                date(previous) - timedelta(hours=cfg.overlap_hours)
                if self.mode == "incremental" and previous
                else datetime(1970, 1, 1, tzinfo=UTC)
            )
            if self.mode == "incremental" and not previous:
                raise ImportFailure("initial_import_required")
        else:
            start = date(progress["window_start"])
        assert start is not None
        window_end = min(end, start + timedelta(days=120))
        offset = progress.get("offset", 0)
        prefix = "lastMod" if self.mode == "incremental" else "pub"
        query = {
            prefix + "StartDate": start.isoformat(),
            prefix + "EndDate": window_end.isoformat(),
            "startIndex": offset,
            "resultsPerPage": cfg.page_size,
        }
        artifact = await self.transport.fetch(
            "nvd",
            "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(query),
            self.run_id,
        )
        parsed, milliseconds = await isolated(
            "source", artifact.path, cfg, source="nvd", offset=offset
        )
        value = parsed["value"]
        values, total, finished = pagination(
            value, "vulnerabilities", offset, cfg.page_size, progress.get("total"), nvd=True
        )
        records, errors = parsed["records"], parsed["errors"]
        done = finished and window_end >= end
        following = {
            "window_start": window_end.isoformat() if finished else start.isoformat(),
            "offset": 0 if finished else offset + len(values),
        }
        if not finished:
            following["total"] = total
        return Page(
            records,
            errors,
            artifact,
            following,
            done,
            {"main": {"watermark": end.isoformat()}},
            milliseconds,
        )

    async def kev(self, progress: dict[str, Any]) -> Page:
        if self.kev_data is None:
            artifact = await self.transport.fetch(
                "cisa_kev",
                "https://www.cisa.gov/sites/default"
                "/files/feeds/known_exploited_vulne"
                "rabilities.json",
                self.run_id,
            )
            parsed, milliseconds = await isolated(
                "source", artifact.path, self.configuration, source="cisa_kev"
            )
            self.kev_data = artifact, parsed, milliseconds
        artifact, parsed, milliseconds = self.kev_data
        value = parsed["value"]
        offset = progress.get("offset", 0)
        following = offset + self.configuration.batch_size
        return Page(
            parsed["records"][offset:following],
            parsed["errors"] if offset == 0 else [],
            artifact,
            {"offset": following},
            following >= len(parsed["records"]),
            {
                "main": {
                    "catalog_version": value["catalogVersion"],
                    "count": value["count"],
                    "watermark": self.upper.isoformat(),
                }
            },
            milliseconds if offset == 0 else 0,
        )

    async def ubuntu(self, progress: dict[str, Any]) -> Page:
        streams = ["active", "not-in-ubuntu", "rejected", "notices"]
        stream_index = progress.get("stream_index", 0)
        stream = streams[stream_index]
        offset = progress.get("offset", 0)
        limit = 20
        params = {
            "limit": limit,
            "offset": offset,
            "order": "newest" if stream == "notices" else "descending",
        }
        if stream != "notices":
            params.update({"sort_by": "updated", "cve_status": stream})
        path = "notices" if stream == "notices" else "cves"
        artifact, value, milliseconds = await self.json(
            "https://ubuntu.com/security/" + path + ".json?" + urlencode(params)
        )
        entries, total, finished = pagination(value, path, offset, limit, progress.get("total"))
        records, errors = convert("ubuntu", entries, offset=offset)
        # Ubuntu notices have no supported modified-since filter: always reconcile their pages.
        previous = self.cursors.get(stream, {}).get("watermark")
        if self.mode == "incremental" and stream != "notices" and previous and entries:
            cutoff = date(previous) - timedelta(hours=self.configuration.overlap_hours)
            timestamps = [
                date(str(v["updated_at"])) if v.get("updated_at") is not None else None
                for v in entries
                if isinstance(v, dict)
            ]
            if any(v is None for v in timestamps):
                raise ImportFailure("ubuntu_missing_modified")
            dates: list[datetime] = [value for value in timestamps if value is not None]
            if dates != sorted(dates, reverse=True):
                raise ImportFailure("ubuntu_order_changed")
            if dates[-1] < cutoff:
                finished = True
        next_index = stream_index + int(finished)
        following = {"stream_index": next_index, "offset": 0 if finished else offset + len(entries)}
        if not finished:
            following["total"] = total
        return Page(
            records,
            errors,
            artifact,
            following,
            next_index == len(streams),
            {s: {"watermark": self.upper.isoformat()} for s in streams},
            milliseconds,
        )

    async def osv(self, progress: dict[str, Any]) -> Page:
        streams = self.configuration.osv_ecosystems
        if not streams:
            raise ImportFailure("osv_ecosystems_required")
        stream_index = progress.get("stream_index", 0)
        ecosystem = streams[stream_index]
        prefix = (
            "https://storage.googleapis.com/osv-vulnerabilities/" + quote(ecosystem, safe="") + "/"
        )
        if self.mode != "incremental":
            artifact, result, milliseconds = await self.archive(
                prefix + "all.zip", progress.get("offset", 0)
            )
            finished = result["done"]
            records, errors = result["records"], result["errors"]
            following = {
                "stream_index": stream_index + int(finished),
                "offset": 0 if finished else result["offset"],
            }
        else:
            previous = self.cursors.get(ecosystem, {}).get("watermark")
            if not previous:
                raise ImportFailure("initial_import_required")
            index = await self.transport.fetch(
                "osv", prefix + "modified_id.csv", self.run_id, kind="csv"
            )
            offset = progress.get("offset", 0)
            if prefix not in self.archives:
                cutoff = date(previous) - timedelta(hours=self.configuration.overlap_hours)
                self.archives[prefix] = index_stream(
                    index.path, offset, self.configuration, cutoff, self.upper
                )
            selection, _ = await anext(self.archives[prefix])
            selected = selection["selected"]
            records = []
            errors = []
            milliseconds = 0.0
            artifact = index
            for position, external in selected:
                artifact = await self.transport.fetch(
                    "osv", prefix + quote(external, safe="") + ".json", self.run_id
                )
                try:
                    value, elapsed = await isolated(
                        "record",
                        artifact.path,
                        self.configuration,
                        source="osv",
                        filename=external + ".json",
                    )
                    records.append(
                        {
                            **value,
                            "position": str(position),
                            "artifact_location": artifact.location,
                            "artifact_sha256": artifact.sha256.hex(),
                            "artifact_size": artifact.size,
                            "artifact_milliseconds": artifact.milliseconds,
                            "original_record_sha256": artifact.sha256.hex(),
                        }
                    )
                except ImportFailure as error:
                    elapsed = 0
                    errors.append({"position": str(position), "code": str(error)})
                milliseconds += elapsed
            finished = selection["done"]
            artifact = index
            following = {
                "stream_index": stream_index + int(finished),
                "offset": 0 if finished else selection["offset"],
            }
        return Page(
            records,
            errors,
            artifact,
            following,
            following["stream_index"] == len(streams),
            {s: {"watermark": self.upper.isoformat()} for s in streams},
            milliseconds,
        )
