"""Separate reader and authentication security identities; no request-selected roles."""

from pathlib import Path
from typing import Literal

from cve_common.config.settings import DatabaseSettings, ServiceSettings
from pydantic import Field, model_validator
from pydantic_settings import SettingsConfigDict

from cve_api.auth.settings import AuthSettings
from cve_api.inventories.settings import InventorySettings
from cve_api.status.models import Settings as StatusSettings


class ApiSettings(ServiceSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_API_")
    service_name: Literal["cve-api"] = "cve-api"
    database: DatabaseSettings
    cve_configuration_file: Path | None = Path("/run/cve-api/import-sources.json")
    status: StatusSettings | None = None
    auth: AuthSettings | None = None
    inventory: InventorySettings | None = None
    allowed_hosts: list[str] = Field(default_factory=lambda: ["cve-api", "localhost", "127.0.0.1"])

    @model_validator(mode="after")
    def api_context(self) -> "ApiSettings":
        if self.database.username != "api_reader":
            raise ValueError("Phase 6 API requires the reader identity")
        if self.status and (
            self.auth is None
            or self.status.database.host != self.database.host
            or self.status.database.port != self.database.port
        ):
            raise ValueError("Status uses the existing database and authenticated API")
        if self.inventory and (
            self.auth is None or self.inventory.database.host != self.auth.database.host
        ):
            raise ValueError("Inventory uses the same database and verified dashboard identity")
        return self
