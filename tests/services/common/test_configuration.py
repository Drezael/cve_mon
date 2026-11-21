"""Configuration priority, distinct roles, private files and safe startup failures."""

from pathlib import Path

import pytest
from cve_api.settings import ApiSettings
from cve_common.config.secrets import SecretError, read_secret
from cve_common.config.settings import DatabaseSettings, ServiceSettings
from cve_common.config.validation import ConfigurationError, load_settings
from pydantic import ValidationError

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    "field,value",
    [
        ("service_name", "wrong"),
        ("app_env", "staging"),
        ("http_port", 0),
        ("http_port", 65536),
        ("ready_timeout", 0),
        ("ready_timeout", 100),
        ("allowed_hosts", ["*"]),
        ("allowed_hosts", []),
        ("log_level", "TRACE"),
    ],
)
def test_invalid_service_settings(field: str, value: object) -> None:
    args: dict[str, object] = {"service_name": "cve-test", "app_env": "test", field: value}
    with pytest.raises(ValidationError):
        ServiceSettings.model_validate(args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("username", "postgres_admin"),
        ("username", "cve_migrator"),
        ("username", "postgres_owner"),
        ("host", "db;evil"),
        ("port", 0),
        ("pool_size", 0),
        ("max_overflow", 100),
        ("connect_timeout", 0),
        ("statement_timeout_ms", 0),
        ("hostaddr", "wrong-address"),
    ],
)
def test_invalid_database_settings(
    db_settings: DatabaseSettings, field: str, value: object
) -> None:
    args = db_settings.model_dump()
    args[field] = value
    with pytest.raises(ValidationError):
        DatabaseSettings.model_validate(args)


def test_priorities_and_no_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("CVE_SERVICE_APP_ENV=development\n")
    monkeypatch.delenv("CVE_SERVICE_APP_ENV", raising=False)
    with pytest.raises(ConfigurationError):
        load_settings(ServiceSettings)
    monkeypatch.setenv("CVE_SERVICE_APP_ENV", "production")
    monkeypatch.setenv("CVE_SERVICE_SERVICE_NAME", "cve-worker")
    monkeypatch.setenv("CVE_SERVICE_HTTP_PORT", "9000")
    assert load_settings(ServiceSettings).http_port == 9000
    assert ServiceSettings(http_port=8001).http_port == 8001  # type: ignore[call-arg]
    assert load_settings(ServiceSettings).app_env == "production"
    monkeypatch.setenv("CVE_API_APP_ENV", "test")
    assert load_settings(ServiceSettings).service_name == "cve-worker"


def test_api_rejects_elevated_context(db_settings: DatabaseSettings) -> None:
    elevated = db_settings.model_copy(update={"username": "dashboard_admin"})
    with pytest.raises(ValidationError):
        ApiSettings(app_env="test", database=elevated)


@pytest.mark.parametrize(
    "fault", ["missing", "empty", "public", "symlink", "newline", "directory", "oversize"]
)
def test_secret_fails_safely(tmp_path: Path, fault: str) -> None:
    path = tmp_path / "input"
    marker = "private-unit-marker"
    path.write_text(marker)
    path.chmod(0o600)
    if fault == "missing":
        path.unlink()
    elif fault == "empty":
        path.write_text("")
    elif fault == "public":
        path.chmod(0o644)
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "absent")
    elif fault == "newline":
        path.write_text(marker + "\nother")
    elif fault == "directory":
        path.unlink()
        path.mkdir()
    else:
        path.write_text(marker * 500)
    with pytest.raises(SecretError) as error:
        read_secret(path)
    assert marker not in str(error.value)
    assert str(path) not in str(error.value)


def test_private_secret_and_repr(db_settings: DatabaseSettings) -> None:
    secret = read_secret(db_settings.password_file)
    assert secret.get_secret_value() == "synthetic-only-secret"
    assert "synthetic-only-secret" not in repr(secret)
    assert "synthetic-only-secret" not in repr(db_settings)


def test_invalid_address_never_reflects_input(db_settings: DatabaseSettings) -> None:
    args = db_settings.model_dump()
    args["hostaddr"] = "private-address-marker"
    with pytest.raises(ValidationError) as error:
        DatabaseSettings.model_validate(args)
    assert "private-address-marker" not in str(error.value)
