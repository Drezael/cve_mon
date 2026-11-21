"""Import installed runtime packages; no path manipulation or service startup."""

import importlib


def main() -> None:
    for name in (
        "cve_common",
        "cve_common.database.engine",
        "cve_common.lifecycle.worker",
        "cve_api.factory",
    ):
        importlib.import_module(name)
    print("Installierte technische Pakete importierbar")


if __name__ == "__main__":
    main()
