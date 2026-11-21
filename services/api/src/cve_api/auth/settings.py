"""Safe configurable authentication policy and explicit private key files."""

from pathlib import Path
from urllib.parse import urlsplit

from cve_common.config.settings import DatabaseSettings
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    database: DatabaseSettings
    administration_database: DatabaseSettings | None = None
    origin: str
    keyring_file: Path = Field(repr=False)
    gateway_file: Path = Field(repr=False)
    argon_memory: int = Field(default=19456, ge=19456, le=65536)
    argon_iterations: int = Field(default=2, ge=2, le=4)
    argon_parallelism: int = Field(default=1, ge=1, le=2)
    argon_concurrency: int = Field(default=2, ge=1, le=2)
    login_limit: int = Field(default=10, ge=3, le=20)
    ip_limit: int = Field(default=60, ge=10, le=100)
    global_limit: int = Field(default=200, ge=20, le=1000)
    challenge_limit: int = Field(default=5, ge=3, le=10)
    admin_idle: int = Field(default=900, ge=60, le=900)
    admin_absolute: int = Field(default=28800, ge=300, le=28800)
    user_idle: int = Field(default=1800, ge=60, le=1800)
    user_absolute: int = Field(default=43200, ge=300, le=43200)
    challenge_seconds: int = Field(default=300, ge=60, le=300)
    reauth_seconds: int = Field(default=300, ge=30, le=300)
    cleanup_seconds: int = Field(default=60, ge=30, le=300)
    totp_window: int = Field(default=1, ge=0, le=1)

    @model_validator(mode="after")
    def valid_context(self) -> "AuthSettings":
        if (
            self.administration_database
            and self.administration_database.username != "dashboard_admin"
        ):
            raise ValueError("Dedicated dashboard administrator identity required")
        parsed = urlsplit(self.origin)
        if (
            self.database.username != "api_security"
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Dedicated security identity and exact HTTPS origin required")
        if self.argon_memory * self.argon_concurrency > 131072:
            raise ValueError("Argon memory budget exceeded")
        if parsed.port == 443:
            object.__setattr__(self, "origin", "https://" + str(parsed.hostname))
        return self
