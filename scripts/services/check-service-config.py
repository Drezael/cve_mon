"""Validate the API's explicitly supplied environment without opening resources."""

from cve_api.settings import ApiSettings
from cve_common.config.secrets import read_secret
from cve_common.config.validation import load_settings


def main() -> None:
    settings = load_settings(ApiSettings)
    read_secret(settings.database.password_file)
    print("Dienstkonfiguration und private Secretdatei gültig")


if __name__ == "__main__":
    main()
