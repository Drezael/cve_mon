"""TLS renewal must preserve the active certificate on invalid input or reload failure."""

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.infrastructure import manage, tls


@pytest.mark.parametrize("failure", [None, "certificate", "nginx"])
def test_tls_refresh_is_validated_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    config = manage.load_config(overrides={"SECRETS_BASE": str(tmp_path / "private")})
    active = config.directory / "tls"
    active.mkdir(parents=True)
    names = {
        "server.crt": "TLS_CERT_FILE",
        "server.key": "TLS_KEY_FILE",
        "client-ca.crt": "CLIENT_CA_FILE",
        "client-ca.crl": "CLIENT_CRL_FILE",
    }
    for name in names:
        (active / name).write_text("previous-" + name)
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    for name, key in names.items():
        (incoming / name).write_text("renewed-" + name)
        config.values[key] = str(incoming / name)
    calls: list[list[str]] = []

    def validate(_config: Any) -> None:
        if failure == "certificate":
            raise ValueError("invalid incoming certificate")

    def compose(_config: Any, arguments: list[str]) -> None:
        calls.append(arguments)
        if failure == "nginx":
            raise subprocess.CalledProcessError(1, "nginx")

    from scripts.inventory import configuration

    monkeypatch.setattr(manage, "certificate_preflight", validate)
    monkeypatch.setattr(manage, "compose", compose)
    monkeypatch.setattr(configuration, "trust", lambda _c, _p: None)
    if failure:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            tls.refresh(config)
        assert all((active / name).read_text() == "previous-" + name for name in names)
        if failure == "certificate":
            assert not calls
    else:
        assert tls.refresh(config)
        assert calls[-1][-2:] == ["-s", "reload"]
        assert all((active / name).read_text() == "renewed-" + name for name in names)
        assert not tls.refresh(config)
