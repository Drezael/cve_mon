"""Strict non-secret environment contracts and private, atomic operator records."""

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from scripts.infrastructure.manage import Config, load_config

ROOT = Path(__file__).resolve().parents[2]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def read(path: Path, *, private: bool = False) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Bounded regular JSON file required")
    if private and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("Private operator record must have mode 0600")
    value = json.loads(
        path.read_text(),
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def atomic(path: Path, value: Any, *, exclusive: bool = False) -> None:
    if path.is_symlink():
        raise ValueError("Operator record must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".pending-" + os.urandom(8).hex())
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def schema(value: dict[str, Any], name: str) -> None:
    document = read(ROOT / "configuration/deployment" / name)
    if list(Draft202012Validator(document).iter_errors(value)):
        raise ValueError("Deployment contract validation failed: " + name)


@dataclass(frozen=True)
class Environment:
    path: Path
    contract: dict[str, Any]
    config: Config

    @property
    def kind(self) -> str:
        return str(self.contract["kind"])

    @property
    def identity(self) -> str:
        value = {"contract": self.contract, "configuration": self.config.values}
        if self.contract.get("migration_plan_file"):
            path = Path(self.contract["migration_plan_file"])
            if not path.is_absolute():
                path = self.path.parent / path
            value["migration_plan"] = read(path)
        return digest(value)

    @property
    def control(self) -> Path:
        return self.config.root / ".runtime/deployment" / self.config.project


def environment(path: Path) -> Environment:
    value = read(path)
    schema(value, "config/configuration.schema.json")
    env_file = Path(value["env_file"])
    if not env_file.is_absolute():
        env_file = path.resolve().parent / env_file
    cfg = load_config(env_file)
    if value["kind"] == "production" and cfg.values["APP_ENV"] != "production":
        raise ValueError("Production requires production application configuration")
    if value["kind"] != "production" and cfg.values["APP_ENV"] != "development":
        raise ValueError("Non-production contracts require development application configuration")
    if value["kind"] in {"integration", "staging"} and not re.fullmatch(
        r"cve-db-test-(?:phase24|release)-[a-z0-9-]{6,40}", cfg.project
    ):
        raise ValueError("Isolated Phase-24 project required for staging/integration")
    if value["kind"] != "production" and cfg.values["INGRESS_BIND_IP"] not in {"127.0.0.1", "::1"}:
        raise ValueError("Non-production deployment must bind loopback")
    return Environment(path.resolve(), value, cfg)
