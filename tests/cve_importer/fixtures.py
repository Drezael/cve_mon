"""Synthetic, source-schema-valid records, never operator credentials or production data."""

from typing import Any


def cve(
    version: str = "5.1.1", state: str = "PUBLISHED", identifier: str = "CVE-2026-12345"
) -> dict[str, Any]:
    metadata = {
        "cveId": identifier,
        "assignerOrgId": "00000000-0000-4000-8000-000000000001",
        "state": state,
        "dateUpdated": "2026-11-07T12:00:00.000Z",
    }
    cna: dict[str, Any] = {
        "providerMetadata": {
            "orgId": "00000000-0000-4000-8000-000000000001",
            "dateUpdated": "2026-11-07T12:00:00.000Z",
        }
    }
    if state == "PUBLISHED":
        cna.update(
            {
                "descriptions": [{"lang": "en", "value": "Synthetic vulnerability example"}],
                "affected": [
                    {
                        "vendor": "fixture",
                        "product": "example",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
                "references": [{"url": "https://example.test/advisory"}],
            }
        )
    else:
        cna["rejectedReasons"] = [{"lang": "en", "value": "Synthetic rejection"}]
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": version,
        "cveMetadata": metadata,
        "containers": {"cna": cna},
    }


def nvd(identifier: str = "CVE-2026-12345") -> dict[str, Any]:
    return {
        "id": identifier,
        "sourceIdentifier": "fixture@example.test",
        "published": "1970-01-01T00:00:00.000",
        "lastModified": "1970-01-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Synthetic source record"}],
        "references": [],
    }


def kev(identifier: str = "CVE-2026-12345") -> dict[str, Any]:
    return {
        "cveID": identifier,
        "vendorProject": "Fixture",
        "product": "Example",
        "vulnerabilityName": "Synthetic example",
        "dateAdded": "2026-11-07",
        "shortDescription": "Synthetic source record",
        "requiredAction": "Apply fixture update",
        "dueDate": "2026-11-28",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": ["CWE-20"],
    }


def catalog(
    items: list[dict[str, Any]] | None = None, version: str = "2026.11.07"
) -> dict[str, Any]:
    rows = items if items is not None else [kev()]
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": "2026-11-07T12:00:00.000Z",
        "count": len(rows),
        "vulnerabilities": rows,
    }


def osv(identifier: str = "GHSA-2345-6789-abcd", withdrawn: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1.7.0",
        "id": identifier,
        "modified": "2026-11-07T12:00:00Z",
        "published": "2026-11-06T12:00:00Z",
        "aliases": ["CVE-2026-12345", "CVE-2026-12346"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2:1.0-1ubuntu1"}],
                    }
                ],
            }
        ],
        **({"withdrawn": "2026-11-07T12:00:00Z"} if withdrawn else {}),
    }


def ubuntu(identifier: str = "CVE-2026-12345") -> dict[str, Any]:
    return {
        "id": identifier,
        "published": "2026-11-06T12:00:00Z",
        "updated_at": "2026-11-07T12:00:00Z",
        "status": "active",
        "packages": [
            {
                "name": "example",
                "source": "https://example.test/source",
                "ubuntu": "example",
                "debian": "example",
                "statuses": [
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "description": "1:2.0-1ubuntu1",
                        "component": "main",
                    }
                ],
            }
        ],
    }
