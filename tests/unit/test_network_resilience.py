"""Connection loss is retryable; infrastructure polling survives raw socket failures."""

import asyncio
import errno
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest
from cve_common.config.settings import DatabaseSettings
from cve_common.jobs.errors import ErrorCode, classify
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker, WorkerSettings


@pytest.mark.parametrize(
    "error",
    [
        ConnectionResetError("reset"),
        ConnectionAbortedError("abort"),
        BrokenPipeError("pipe"),
        ConnectionRefusedError("refused"),
        socket.gaierror("dns"),
        OSError(errno.ENETUNREACH, "offline"),
    ],
)
def test_socket_failures_retry_instead_of_becoming_permanent(error: BaseException) -> None:
    result = classify(error)
    assert result.code == ErrorCode.NETWORK and result.retry


def test_missing_file_is_still_a_permanent_error() -> None:
    assert not classify(FileNotFoundError("missing config")).retry


@pytest.mark.parametrize("operation", ["request_recovery", "recover", "claim"])
async def test_polling_stays_alive_through_connection_loss(operation: str, tmp_path: Path) -> None:
    stop = asyncio.Event()
    attempts = 0

    async def intermittent(*_args: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            raise ConnectionResetError("Simulated disconnected backend")
        stop.set()
        return None if operation != "recover" else 0

    repository = SimpleNamespace(
        request_recovery=AsyncMock(),
        recover=AsyncMock(return_value=0),
        claim=AsyncMock(return_value=None),
    )
    setattr(repository, operation, intermittent)
    settings = WorkerSettings(
        service_name="cve-test",
        app_env="test",
        database=DatabaseSettings(
            host="cve-postgres",
            username="importer",
            password_file=tmp_path / "secret",
            ca_file=tmp_path / "ca",
        ),
        concurrency=1,
        poll_seconds=0.05,
        lease_seconds=1,
        heartbeat_seconds=0.1,
    )
    worker = Worker(cast(JobRepository, repository), settings)
    await asyncio.wait_for(worker.run(stop), 2)
    assert attempts == 4 and not worker.active


async def test_git_drains_large_error_output_and_exposes_only_safe_diagnosis(
    tmp_path: Path,
) -> None:
    import sys
    from uuid import uuid4

    from cve_common.jobs.errors import JobError
    from cve_importer.contracts import Configuration
    from cve_importer.git_source import GitSource

    source = GitSource(SimpleNamespace(scratch=tmp_path, ca_file=None), uuid4(), Configuration())  # type: ignore[arg-type]
    source.prefix = lambda: [  # type: ignore[method-assign]
        sys.executable,
        "-c",
        "import sys;sys.stderr.write('Could not resolve host: private-diagnostic-token '+ "
        "'x'*1048576);sys.exit(1)",
    ]
    with pytest.raises(JobError) as caught:
        await asyncio.wait_for(source.git("ignored"), 2)
    assert caught.value.code == ErrorCode.NETWORK
    assert caught.value.diagnostic_code == "GIT_DNS_FAILED"
    assert "private-diagnostic-token" not in str(caught.value)
