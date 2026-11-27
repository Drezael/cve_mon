"""Explicit code-level test doubles for disposable labs; never an .env configuration API."""

import json
from dataclasses import replace
from pathlib import Path

from scripts.infrastructure.manage import ROOT, Config, load_config
from scripts.infrastructure.policy import INTERNAL_DEFAULTS


def load_test_config(
    env_file: Path | None = None,
    overrides: dict[str, str] | None = None,
    root: Path = ROOT,
) -> Config:
    supplied = dict(overrides or {})
    fixture_paths = {
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
        "TLS_TRUST_FILE",
        "CLIENT_CA_FILE",
        "CLIENT_CRL_FILE",
    }
    internal = {
        key: supplied.pop(key)
        for key in tuple(supplied)
        if key in INTERNAL_DEFAULTS or key in fixture_paths
    }
    if "CLIENT_CA_FILE" in internal and "CLIENT_CRL_FILE" not in internal:
        internal["CLIENT_CRL_FILE"] = str(
            Path(internal["CLIENT_CA_FILE"]).with_name("client-ca.crl")
        )
    # Host IDs used to be explicit in older fixtures; the controller now derives them.
    supplied.pop("NGINX_UID", None)
    supplied.pop("NGINX_GID", None)
    config = load_config(env_file, supplied, root)
    if not internal:
        return config
    if not config.project.startswith(("cve-db-test-", "cve-test-", "cve-mail-test-")):
        raise ValueError("Synthetic internal settings require an isolated test project")
    config = replace(config, values={**config.values, **internal})
    if "STATUS_COLLECTOR_PAUSED" in internal:
        folder = root / ".runtime/test-policy" / config.project
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        overlay = folder / "status.json"
        overlay.write_text(
            json.dumps(
                {
                    "services": {
                        "cve-api": {
                            "environment": {
                                "CVE_API_STATUS__PAUSED": internal["STATUS_COLLECTOR_PAUSED"],
                            }
                        }
                    }
                }
            )
        )
        config = replace(config, compose_overrides=(*config.compose_overrides, overlay))
    return config
