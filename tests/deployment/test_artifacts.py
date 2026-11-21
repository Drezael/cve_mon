"""Offline archives cannot redirect paths, import foreign tags or substitute image configs."""

import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from scripts.deployment.artifacts import archive_matches


@pytest.mark.parametrize("mutation", [None, "tag", "config", "symlink", "traversal"])
def test_offline_archive_identity_and_members(tmp_path: Path, mutation: str | None) -> None:
    configuration = b'{"architecture":"amd64"}'
    item: dict[str, Any] = {
        "source_reference": "cve-api:test",
        "config_digests": ["sha256:" + hashlib.sha256(configuration).hexdigest()],
    }
    manifest = [{"Config": "config.json", "RepoTags": [item["source_reference"]], "Layers": []}]
    if mutation == "tag":
        manifest[0]["RepoTags"] = ["unrelated:latest"]
    if mutation == "config":
        configuration = b'{"architecture":"substituted"}'
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        for name, content in [
            ("manifest.json", json.dumps(manifest).encode()),
            ("config.json", configuration),
        ]:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        if mutation in {"symlink", "traversal"}:
            member = tarfile.TarInfo("link" if mutation == "symlink" else "../outside")
            if mutation == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
            archive.addfile(member)
    if mutation:
        with pytest.raises(ValueError):
            archive_matches(path, item)
    else:
        archive_matches(path, item)
