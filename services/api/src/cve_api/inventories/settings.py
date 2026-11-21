"""Explicit ingestion context, PKI trust and conservative finite upload budgets."""

from pathlib import Path
from urllib.parse import urlsplit

from cve_common.config.settings import DatabaseSettings
from pydantic import BaseModel, ConfigDict, Field, model_validator


class InventorySettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    database: DatabaseSettings
    origin: str
    gateway_file: Path = Field(repr=False)
    token_key_file: Path = Field(repr=False)
    client_ca_file: Path
    client_crl_file: Path
    max_bytes: int = Field(default=10485760, ge=1024, le=10485760)
    max_request_bytes: int = Field(default=11534336, ge=2048, le=11534336)
    max_depth: int = Field(default=32, ge=8, le=64)
    max_nodes: int = Field(default=750000, ge=100, le=750000)
    parser_seconds: int = Field(default=15, ge=2, le=15)
    concurrent_uploads: int = Field(default=1, ge=1, le=1)
    global_rate: int = Field(default=120, ge=1, le=1000)
    ip_rate: int = Field(default=60, ge=1, le=1000)
    client_rate: int = Field(default=60, ge=1, le=1000)
    token_rate: int = Field(default=30, ge=1, le=1000)
    server_rate: int = Field(default=30, ge=1, le=1000)
    user_rate: int = Field(default=10, ge=1, le=1000)

    @model_validator(mode="after")
    def context(self) -> "InventorySettings":
        parsed = urlsplit(self.origin)
        if (
            self.database.username != "api_ingest"
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Dedicated ingestion identity and exact technical HTTPS origin required"
            )
        object.__setattr__(
            self, "max_request_bytes", min(self.max_request_bytes, self.max_bytes + 1048576)
        )
        if self.max_request_bytes < self.max_bytes + 1024:
            raise ValueError("Multipart overhead required")
        return self
