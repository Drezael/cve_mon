"""Real offline volume adoption and Postfix bind backup/restore in disposable projects."""

import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.infrastructure import mail, mounts, secrets, storage
from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import (
    Config,
    compose,
    docker_command,
    load_config,
    resolved,
    run,
)

pytestmark = pytest.mark.infrastructure


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    # This lab supplies its own minimal Compose model without repository configuration mounts.
    monkeypatch.setattr(mounts, "prepare", lambda _config: None)
    monkeypatch.setattr(secrets, "prepare", lambda _config: None)
    return replace(
        load_config(
            overrides={
                "COMPOSE_PROJECT_NAME": "cve-bind-test-" + uuid4().hex[:10],
                "MOUNT_BASE": "./.runtime",
                "SECRETS_BASE": "./.runtime",
            }
        ),
        root=tmp_path,
    )


def test_image_declared_volume_paths_are_explicitly_covered() -> None:
    model = resolved(load_config())
    for name in ("cve-postgres", "cve-mail-relay", "cve-n8n", "cve-nginx"):
        service = model["services"][name]
        metadata = json.loads(
            run([*docker_command(), "image", "inspect", service["image"]]).stdout
        )[0]
        declared = {p.rstrip("/") for p in metadata["Config"].get("Volumes") or {}}
        explicit = {p["target"].rstrip("/") for p in service.get("volumes", [])}
        explicit.update(p.split(":")[0].rstrip("/") for p in service.get("tmpfs", []))
        assert declared <= explicit, name


def test_legacy_store_is_copied_with_ownership_and_original_preserved(config: Config) -> None:
    name = config.project + "_cve_mailhog_data"
    run(
        [
            *docker_command(),
            "volume",
            "create",
            "--label",
            "com.docker.compose.project=" + config.project,
            "--label",
            "com.docker.compose.volume=cve_mailhog_data",
            name,
        ]
    )
    try:
        storage.helper(
            config,
            ["type=volume,source=" + name + ",target=/target"],
            "echo retained > /target/message; chown -R 1000:1000 /target; "
            "chmod 700 /target; chmod 600 /target/message",
        )
        storage.prepare(config, ["cve-mailhog"])
        target = storage.path(config, "cve_mailhog_data")
        storage.helper(
            config,
            ["type=bind,source=" + str(target) + ",target=/target,readonly"],
            'test "$(cat /target/message)" = retained; '
            'test "$(stat -c %u:%g:%a /target/message)" = 1000:1000:600',
        )
        storage.helper(
            config,
            ["type=volume,source=" + name + ",target=/target,readonly"],
            'test "$(cat /target/message)" = retained',
        )
        storage.prepare(config, ["cve-mailhog"])
    finally:
        storage.remove(config)
        run([*docker_command(), "volume", "rm", name])


def test_queue_bind_backup_and_restore_without_anonymous_volumes(config: Config) -> None:
    before = set(
        run([*docker_command(), "volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
    )
    storage.prepare(config, ["cve-mail-relay"])
    queue = storage.path(config, "cve_postfix_queue")
    tmpfs = storage.image_tmpfs(REFERENCES["mail"])
    destinations = [tmpfs[i + 1].split(":")[0] for i in range(0, len(tmpfs), 2)]
    model = {
        "services": {
            "cve-mail-relay": {
                "image": REFERENCES["mail"],
                "entrypoint": ["/bin/sh", "-c", "sleep 300"],
                "network_mode": "none",
                "read_only": True,
                "labels": {"org.cve-monitoring.project": config.project},
                "tmpfs": [
                    p + ":rw,noexec,nosuid,size=16m"
                    for p in destinations
                    if p.rstrip("/") != "/var/spool/postfix"
                ],
                "volumes": [{"type": "bind", "source": str(queue), "target": "/var/spool/postfix"}],
            }
        }
    }
    (config.root / "compose.yml").write_text(json.dumps(model))
    (config.root / "infrastructure/compose").mkdir(parents=True, exist_ok=True)
    (config.root / "infrastructure/compose/development.yml").write_text('{"services": {}}')
    try:
        compose(config, ["up", "-d", "cve-mail-relay"])
        assert not any(m["Type"] == "volume" for m in mail.container(config)["Mounts"])
        storage.helper(
            config,
            ["type=bind,source=" + str(queue) + ",target=/target"],
            "mkdir /target/incoming; echo retained > /target/incoming/message; "
            "chown -R 100:101 /target/incoming; chmod 700 /target/incoming",
        )
        backup = config.root / "backup"
        mail.backup(config, backup)
        storage.helper(
            config,
            ["type=bind,source=" + str(queue) + ",target=/target"],
            "rm -rf /target/incoming",
        )
        mail.restore(config, backup)
        storage.helper(
            config,
            ["type=bind,source=" + str(queue) + ",target=/target,readonly"],
            'test "$(cat /target/incoming/message)" = retained; '
            'test "$(stat -c %u:%g:%a /target/incoming)" = 100:101:700',
        )
        after = set(
            run([*docker_command(), "volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
        )
        assert after == before
    finally:
        compose(config, ["down"])
        storage.remove(config)
