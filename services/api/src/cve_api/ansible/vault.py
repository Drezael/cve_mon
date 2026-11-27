"""Personal vault setup and password rotation; no secret read/export endpoints."""

from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cve_common.concurrency import WorkBusy
from cve_common.ssh_credentials import KeyringError
from cve_common.user_vault import UserVaultKeyring, password_envelope, unlock_password
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from cve_api.auth.audit import record
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import execute, one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import load_principal

router = APIRouter(prefix="/api/v1/dashboard/me/ansible-vault", tags=["personal-vault"])


class VaultPassword(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    password: SecretStr = Field(min_length=15, max_length=256)
    password_confirmation: SecretStr = Field(min_length=15, max_length=256)
    current_password: SecretStr | None = Field(default=None, min_length=15, max_length=256)

    @model_validator(mode="after")
    def matching(self) -> "VaultPassword":
        if self.password.get_secret_value() != self.password_confirmation.get_secret_value():
            raise ValueError("Vault passwords must match")
        return self


class VaultState(BaseModel):
    configured: bool


def keyring(request: Request) -> UserVaultKeyring:
    auth, _ = transport(request)
    return UserVaultKeyring(Path(auth.settings.keyring_file).with_name("ssh-keys.json"))


@router.get("", response_model=VaultState)
async def status(request: Request) -> dict[str, bool]:
    auth, _ = transport(request)
    async with security_transaction(auth.database, mutation=False) as s:
        actor, _ = await load_principal(auth, s, request.cookies.get(SESSION_COOKIE))
        vault = await one(
            s, "SELECT user_id FROM security.ansible_vaults WHERE user_id=:id", id=actor.user_id
        )
        return {"configured": vault is not None}


@router.put("", response_model=VaultState)
async def save(body: VaultPassword, request: Request) -> dict[str, bool]:
    auth, _ = transport(request)
    # Persist reauthentication consumption before expensive verification, even on failure.
    async with security_transaction(auth.database) as s:
        actor, current = await load_principal(
            auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request)
        )
        await auth.consume_reauth(s, current)
        vault = await one(
            s, "SELECT * FROM security.ansible_vaults WHERE user_id=:id", id=actor.user_id
        )
    await auth.limits.check("vault-user", str(actor.user_id), 5, 300)
    await auth.limits.check("vault-session", str(current["id"]), 5, 300)

    def derive() -> dict[str, Any]:
        if vault:
            if body.current_password is None:
                raise Denied(422, "current_vault_password_required")
            key = unlock_password(actor.user_id, body.current_password.get_secret_value(), vault)
            salt, wrapped = password_envelope(actor.user_id, body.password.get_secret_value(), key)
            return {"salt": salt, "password_envelope": wrapped}
        return keyring(request).create(actor.user_id, body.password.get_secret_value())

    try:
        values = await auth.vault_work.run(derive)
    except InvalidTag:
        raise Denied(422, "invalid_vault_password") from None
    except WorkBusy:
        raise Denied(429, "vault_busy") from None
    except KeyringError:
        raise Denied(503, "vault_key_unavailable") from None

    async with security_transaction(auth.database) as s:
        fresh, session = await load_principal(
            auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request)
        )
        if fresh.user_id != actor.user_id or session["auth_version"] != current["auth_version"]:
            raise Denied(409, "vault_authorization_changed")
        latest = await one(
            s,
            "SELECT * FROM security.ansible_vaults WHERE user_id=:id FOR UPDATE",
            id=actor.user_id,
        )
        if latest != vault:
            raise Denied(412, "vault_changed")
        if vault:
            await execute(
                s,
                "UPDATE security.ansible_vaults SET salt=:salt,"
                "password_envelope=:password_envelope,updated_at=clock_timestamp() "
                "WHERE user_id=:id",
                id=actor.user_id,
                **values,
            )
        else:
            await execute(
                s,
                "INSERT INTO security.ansible_vaults(user_id,salt,password_envelope,"
                "key_id,runtime_envelope) VALUES(:id,:salt,:password_envelope,:key_id,"
                ":runtime_envelope)",
                id=actor.user_id,
                **values,
            )
        await record(s, "ansible_vault_changed", actor.user_id)
    return {"configured": True}
