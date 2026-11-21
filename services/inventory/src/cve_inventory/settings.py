"""Explicit identity and bounded concurrency for isolated normalizer subprocesses."""

from typing import Literal

from cve_common.jobs.worker import WorkerSettings
from pydantic import Field, model_validator
from pydantic_settings import SettingsConfigDict


class InventorySettings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_INVENTORY_")
    service_name: Literal["cve-inventory"] = "cve-inventory"
    concurrency: int = Field(default=1, ge=1, le=2)
    batch_size: int = Field(default=1, ge=1, le=2)

    @model_validator(mode="after")
    def identity(self) -> "InventorySettings":
        if self.database.username != "inventory_processor":
            raise ValueError("Inventory identity required")
        return self
