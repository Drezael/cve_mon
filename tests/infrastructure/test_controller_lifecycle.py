"""Real root-controller stop/down retains PostgreSQL data in its own disposable project."""

import os
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, docker_command, load_config, run

pytestmark = pytest.mark.infrastructure


def test_root_controller_retains_bind_data_on_stop_and_down(repository_root: Path) -> None:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-controller-" + uuid4().hex[:10]}
    )
    base = repository_root / ".runtime/controller-tests" / config.project
    base.mkdir(parents=True, mode=0o700)
    env = base / "platform.env"
    env.write_text(
        "".join(key + "=" + value + "\n" for key, value in sorted(config.external_values.items()))
    )
    env.chmod(0o600)
    command = [str(repository_root / "cve_mon"), "--env-file", str(env)]
    if os.environ.get("CVE_DOCKER_SUDO") == "1":
        command.append("--sudo")
    marker = 'printf retained > "$PGDATA/controller-retention"'
    created = False
    try:
        db.prepare(config)
        created = True
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-postgres"])
        container = db.container_id(config)
        run([*docker_command(), "exec", container, "sh", "-c", marker])
        for action in ["stop", "down"]:
            result = subprocess.run(
                [*command, action],
                cwd=base,
                env=os.environ,
                capture_output=True,
                text=True,
                check=False,
                timeout=90,
            )
            assert result.returncode == 0, result.stderr
            assert (config.mount_base / "storage" / config.project / "postgres-data").is_dir()
            compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-postgres"])
            value = run(
                [
                    *docker_command(),
                    "exec",
                    db.container_id(config),
                    "sh",
                    "-c",
                    'cat "$PGDATA/controller-retention"',
                ]
            ).stdout
            assert value == "retained"
    finally:
        if created:
            db.cleanup_test(config)
        env.unlink(missing_ok=True)
