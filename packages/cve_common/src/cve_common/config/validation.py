"""Safe startup diagnostics without Pydantic input/context or secret material."""

from collections.abc import Callable
from typing import cast

from pydantic import ValidationError
from pydantic_settings import SettingsError

from cve_common.config.settings import ServiceSettings


class ConfigurationError(ValueError):
    """Controlled public startup failure."""


def load_settings[T: ServiceSettings](settings_type: type[T]) -> T:
    try:
        return cast(Callable[[], T], settings_type)()
    except (ValidationError, SettingsError):
        raise ConfigurationError("Invalid or missing service configuration") from None
