"""Missing, replayed and contradictory integration evidence cannot pass the combined gate."""

import json
from pathlib import Path

import pytest

from scripts.testing import merge_campaign


@pytest.mark.parametrize("damage", [None, "source", "missing", "duplicate", "junit", "setup_error"])
def test_campaign_evidence_requires_exact_source_and_complete_junit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str | None
) -> None:
    source = {"commit": "fixture", "source_sha256": "a" * 64}
    monkeypatch.setattr(merge_campaign, "identity", lambda _: source)
    monkeypatch.setattr(merge_campaign, "groups", lambda: [("unit", []), ("native", [])])
    inputs = tmp_path / "shards"
    for index, key in enumerate(["unit", "native"]):
        shard = inputs / str(index)
        shard.mkdir(parents=True)
        result = {
            "batch": key,
            "returncode": 0,
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        }
        summary = {
            "source": source,
            "source_unchanged": True,
            "missing_batches": [],
            "results": [result],
        }
        if damage == "source" and index == 1:
            summary["source"] = {"commit": "old", "source_sha256": "b" * 64}
        if damage == "missing" and index == 1:
            summary["results"] = []
        if damage == "duplicate" and index == 1:
            result["batch"] = "unit"
        if damage == "setup_error" and index == 1:
            result["errors"] = 1
        (shard / "summary.json").write_text(json.dumps(summary))
        failures = "1" if damage == "junit" and index == 1 else "0"
        (shard / (key + ".xml")).write_text(
            f'<testsuites><testsuite tests="1" failures="{failures}" '
            'errors="0" skipped="0" /></testsuites>'
        )
    if damage:
        with pytest.raises(ValueError):
            merge_campaign.merge(inputs, tmp_path / "merged")
    else:
        merge_campaign.merge(inputs, tmp_path / "merged")
        combined = json.loads((tmp_path / "merged/summary.json").read_text())
        assert combined["complete_selection"] and len(combined["results"]) == 2
