"""Combine explicit reruns by test identity while retaining original reports and their failures."""

import copy
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def merge_reports(sources: list[Path], target: Path) -> dict[str, Any]:
    if not sources or any(not p.is_file() for p in sources):
        raise ValueError("Explicit complete source reports required")
    cases: dict[tuple[str, str], ET.Element] = {}
    provenance = []
    for source in sources:
        values = list(ET.parse(source).iter("testcase"))
        if not values:
            raise ValueError("Empty test report")
        for case in values:
            identity = (case.get("classname", ""), case.get("name", ""))
            if not all(identity):
                raise ValueError("Stable test identity required")
            cases[identity] = copy.deepcopy(case)
        provenance.append(
            {
                "path": source.name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "cases": len(values),
            }
        )
    counts = {
        tag: sum(c.find(tag) is not None for c in cases.values())
        for tag in ["failure", "error", "skipped"]
    }
    suite = ET.Element(
        "testsuite",
        {
            "name": "explicit-latest-results",
            "tests": str(len(cases)),
            "failures": str(counts["failure"]),
            "errors": str(counts["error"]),
            "skipped": str(counts["skipped"]),
        },
    )
    for case in cases.values():
        suite.append(case)
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(target, encoding="utf-8", xml_declaration=True)
    metadata = {
        "method": "last result per classname/name; originals preserved",
        "sources_in_order": provenance,
        "distinct_cases": len(cases),
        **counts,
    }
    target.with_suffix(".sources.json").write_text(json.dumps(metadata, indent=2))
    return metadata
