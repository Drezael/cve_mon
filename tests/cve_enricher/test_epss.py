"""Independent FIRST format, Decimal, gzip integrity and closed HTTPS transport tests."""

import gzip
from datetime import date
from pathlib import Path

import httpx
import pytest
from cve_enricher.contracts import Configuration, EnrichmentError
from cve_enricher.epss import Client, allowed, stream

from tests.cve_importer.test_pipeline import wire_response

pytestmark = pytest.mark.cve_enricher
HEADER = b"#model_version:v2026.06.15,score_date:2026-11-07T12:00:00Z\ncve,epss,percentile\n"


async def test_stream_valid_decimal_boundary_and_batches(tmp_path: Path) -> None:
    path = tmp_path / "day.gz"
    path.write_bytes(
        gzip.compress(HEADER + b"CVE-2026-12345,0.123456789,0.987654321\nCVE-2026-12346,0,1\n")
    )
    result = [
        page
        async for page, _ in stream(
            path, Configuration(epss_min_rows=1, epss_batch_size=1), date(2026, 11, 7)
        )
    ]
    assert result[1]["rows"][0]["score"] == "0.123456789"
    assert result[1]["rows"][0]["percentile"] == "0.987654321"
    assert result[-1]["count"] == 2


@pytest.mark.parametrize(
    "body",
    [
        b"CVE-2026-12345,-0.1,0.5\n",
        b"CVE-2026-12345,1.1,0.5\n",
        b"CVE-2026-12345,NaN,0.5\n",
        b"CVE-2026-12345,Infinity,0.5\n",
        b"CVE-2026-12345,0.1,2\n",
        b"CVE-2026-12345,0.1,-1\n",
        b"CVE-2026-12345,0.0000000000000000001,0.5\n",
        b"CVE-2026-12345,0.1,0.5\nCVE-2026-12345,0.2,0.6\n",
        b"../bad,0.1,0.5\n",
        b"CVE-2026-12345,0.1\n",
        b"CVE-2026-12345,0.1,0.5,extra\n",
        b"",
    ],
)
async def test_invalid_day_is_never_complete(tmp_path: Path, body: bytes) -> None:
    path = tmp_path / "day.gz"
    path.write_bytes(gzip.compress(HEADER + body))
    with pytest.raises(EnrichmentError):
        async for _, _done in stream(path, Configuration(epss_min_rows=1), None):
            assert not _done


@pytest.mark.parametrize("case", ["metadata", "header", "date", "crc", "size"])
async def test_metadata_gzip_and_limits(tmp_path: Path, case: str) -> None:
    raw = HEADER + b"CVE-2026-12345,0.1,0.5\n"
    if case == "metadata":
        raw = raw.replace(b"model_version", b"unknown")
    if case == "header":
        raw = raw.replace(b"cve,epss,percentile", b"cve,percentile,epss")
    if case == "date":
        raw = raw.replace(b"2026-11-07T", b"2026-11-06T")
    if case == "size":
        raw += b"CVE-2026-12346,0.2,0.4\n" * 100
    value = gzip.compress(raw)
    if case == "crc":
        value = value[:-4]
    path = tmp_path / "day.gz"
    path.write_bytes(value)
    with pytest.raises(EnrichmentError):
        async for _page, _done in stream(
            path, Configuration(epss_min_rows=1, epss_max_unpacked=1024), date(2026, 11, 7)
        ):
            assert not _done


@pytest.mark.parametrize(
    "url",
    [
        "http://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "https://evil.example/epss_scores-current.csv.gz",
        "https://127.0.0.1/epss_scores-current.csv.gz",
        "https://epss.empiricalsecurity.com:444/epss_scores-current.csv.gz",
        "https://epss.empiricalsecurity.com/../secret",
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz?secret=x",
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz#fragment",
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz/extra",
    ],
)
def test_epss_url_forbidden(url: str) -> None:
    with pytest.raises(EnrichmentError):
        allowed(url)


async def test_redirect_forbidden_without_fallback(tmp_path: Path) -> None:
    seen = []

    def reply(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return wire_response(302, headers={"Location": "https://127.0.0.1/private"})

    client = Client(
        Configuration(epss_min_rows=1),
        tmp_path,
        client=httpx.AsyncClient(transport=httpx.MockTransport(reply)),
    )
    try:
        with pytest.raises(EnrichmentError):
            await client.download(None)
        assert len(seen) == 1
        assert not list(tmp_path.glob("*.csv.gz"))
    finally:
        await client.close()


async def test_first_redirect_and_real_binary_content_type(tmp_path: Path) -> None:
    seen: list[str] = []

    def reply(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if len(seen) == 1:
            return wire_response(302, headers={"Location": "epss_scores-2026-11-07.csv.gz"})
        return wire_response(
            200,
            content=gzip.compress(HEADER + b"CVE-2026-12345,0.1,0.5\n"),
            headers={"Content-Type": "binary/octet-stream"},
        )

    client = Client(
        Configuration(epss_min_rows=1),
        tmp_path,
        client=httpx.AsyncClient(transport=httpx.MockTransport(reply)),
    )
    try:
        path, digest, url = await client.download(None)
        assert path.is_file() and len(digest) == 64
        assert url == "https://epss.empiricalsecurity.com/epss_scores-2026-11-07.csv.gz"
        assert len(seen) == 2
    finally:
        await client.close()


async def test_epss_batches_are_independent_of_enrichment_batches(tmp_path: Path) -> None:
    path = tmp_path / "day.gz"
    path.write_bytes(
        gzip.compress(
            HEADER + b"".join(f"CVE-2026-{i},0.1,0.5\n".encode() for i in range(10000, 10005))
        )
    )
    pages = [
        page
        async for page, _ in stream(
            path, Configuration(epss_min_rows=1, batch_size=1, epss_batch_size=3), None
        )
    ]
    assert [len(page["rows"]) for page in pages if "rows" in page] == [3, 2]
    assert pages[-1]["count"] == 5
