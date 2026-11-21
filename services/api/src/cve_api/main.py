"""One bounded Uvicorn process with proxy-header interpretation disabled."""

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.logging.setup import configure_logging

from cve_api.settings import ApiSettings


def main() -> None:
    settings = load_settings(ApiSettings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_api.factory:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.http_port,
        workers=1,
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=10,
        limit_concurrency=32,
        backlog=64,
    )


if __name__ == "__main__":
    main()
