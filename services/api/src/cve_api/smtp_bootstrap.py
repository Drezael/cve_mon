"""Compose SMTP defaults seed one encrypted central configuration, never overwrite it."""

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from cve_common.smtp_settings import SMTPKeyring, SMTPUpdate
from sqlalchemy import text

from cve_api.auth.service import AuthService
from cve_api.auth.transactions import security_transaction


async def bootstrap(auth: AuthService, values: Mapping[str, str] | None = None) -> None:
    values = os.environ if values is None else values
    if not values.get("CVE_SMTP_HOST", "").strip():
        return
    async with security_transaction(auth.database) as s:
        await s.execute(text("SELECT pg_advisory_xact_lock(7353001)"))
        if (
            await s.execute(
                text("SELECT 1 FROM automation.smtp_configs WHERE owner_id IS NULL LIMIT 1")
            )
        ).first():
            return
        try:
            body = SMTPUpdate.model_validate(
                {
                    "version": 0,
                    "enabled": True,
                    "host": values["CVE_SMTP_HOST"],
                    "port": values.get("CVE_SMTP_PORT", "587"),
                    "sender": values.get("CVE_SMTP_SENDER", ""),
                    "username": values.get("CVE_SMTP_USERNAME", ""),
                    "password": values.get("CVE_SMTP_PASSWORD", ""),
                }
            )
            if not body.is_mailhog and (
                not body.username or not body.password or not body.password.get_secret_value()
            ):
                raise ValueError("incomplete_credentials")
        except ValueError:
            # Pydantic errors contain raw input. Never chain or log them.
            raise ValueError("Invalid initial SMTP configuration; check SMTP variables") from None
        identity = uuid4()
        ring = SMTPKeyring(Path(auth.settings.keyring_file).with_name("smtp-keys.json"))
        key, cipher = ring.encrypt(
            identity,
            {
                "username": body.username,
                "password": body.password.get_secret_value() if body.password else "",
            },
        )
        await s.execute(
            text("SELECT automation.bootstrap_smtp(:id,CAST(:config AS jsonb),:key,:cipher)"),
            {
                "id": identity,
                "config": json.dumps(body.model_dump(exclude={"version", "username", "password"})),
                "key": key,
                "cipher": cipher,
            },
        )
    logging.getLogger("cve.smtp").info("initial_smtp_configuration_queued")
