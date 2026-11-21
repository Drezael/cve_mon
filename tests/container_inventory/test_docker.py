"""Real Syft against disposable images: image cache, live filesystem and mounted application."""

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.infrastructure
ROOT = Path(__file__).resolve().parents[2]


def docker(*args: str) -> str:
    return subprocess.run(
        ["sudo", "-n", "docker", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def test_actual_image_runtime_and_mount_packages(tmp_path: Path) -> None:
    tag = "cve-sbom-test-" + uuid4().hex
    name = tag + "-container"
    package = tmp_path / "package.json"
    package.write_text(json.dumps({"name": "pac-resolver", "version": "4.2.0"}))
    (tmp_path / "Dockerfile").write_text(
        "FROM node:24-alpine3.24\n"
        "COPY package.json /app/node_modules/pac-resolver/package.json\n"
        'CMD ["sleep","600"]\n'
    )
    mounted = tmp_path / "mounted"
    (mounted / "node_modules/mount-example").mkdir(parents=True)
    (mounted / "node_modules/mount-example/package.json").write_text(
        json.dumps({"name": "mount-example", "version": "1.0.0"})
    )
    try:
        docker("build", "--network=none", "-t", tag, str(tmp_path))
        cid = docker(
            "run",
            "-d",
            "--name",
            name,
            "--mount",
            "type=bind,source=" + str(mounted) + ",target=/opt/application,readonly",
            tag,
        )
        image = docker("inspect", "--format", "{{.Image}}", cid)
        # Mutate only this disposable fixture, proving runtime inventory differs from the image.
        docker(
            "exec",
            cid,
            "sh",
            "-c",
            'printf \'{"name":"pac-resolver","version":"5.0.0"}\' '
            "> /app/node_modules/pac-resolver/package.json",
        )
        program = (
            """
import json,tempfile
from pathlib import Path
from scripts.container_inventory.collector import Collector
with tempfile.TemporaryDirectory() as tmp:
 c=Collector(SYFT,'/usr/bin/docker','unix:///var/run/docker.sock',Path(tmp)/'cache',['/opt/application'])
 image=c.image(IMAGE)
 assert image==c.image(IMAGE)
 entries=c.collect({'container_id':CID,'image_id':IMAGE,'state':'running'}, {IMAGE:image})
 print(json.dumps(entries))
""".replace("SYFT", repr(str(ROOT / ".runtime/syft/syft")))
            .replace("IMAGE", repr(image))
            .replace("CID", repr(cid))
        )
        result = subprocess.run(
            ["sudo", "-n", sys.executable, "-c", program],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert result.returncode == 0, result.stderr
        entries = json.loads(result.stdout)
        assert all(e["status"] == "complete" for e in entries), [
            (e["scope"], e["status"]) for e in entries
        ]
        versions = {
            e["scope"]: {p["name"]: p["version"] for p in e["document"]["packages"]}
            for e in entries
        }
        assert versions["image"]["pac-resolver"] == "4.2.0"
        assert versions["runtime"]["pac-resolver"] == "5.0.0"
        assert versions["mount"]["mount-example"] == "1.0.0"
        assert "mount-example" not in versions["runtime"]
    finally:
        subprocess.run(["sudo", "-n", "docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["sudo", "-n", "docker", "image", "rm", tag], capture_output=True)
