"""Legacy activation receipt cleanup; workflow installation lives in the n8n container."""

from scripts.infrastructure.manage import Config
from scripts.notifications.manage import n8n_directory


def activated(config: Config) -> None:
    (n8n_directory(config) / "config/watchdog-install.pending").unlink(missing_ok=True)
