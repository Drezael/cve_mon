"""Dedicated dispatcher identity and private operator target file."""

from pathlib import Path
from typing import Literal

from cve_common.jobs.worker import WorkerSettings
from pydantic import model_validator
from pydantic_settings import SettingsConfigDict


class DispatcherSettings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_DISPATCHER_")
    service_name: Literal["cve-event-dispatcher"] = "cve-event-dispatcher"
    targets_file: Path

    @model_validator(mode="after")
    def dispatcher_identity(self) -> "DispatcherSettings":
        if self.database.username != "event_dispatcher":
            raise ValueError("Dispatcher identity required")
        return self
