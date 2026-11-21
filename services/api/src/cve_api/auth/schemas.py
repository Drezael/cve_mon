"""Strict bounded input, never reflect credentials in validation errors."""

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Login(Input):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=256)


class OTP(Input):
    code: SecretStr = Field(min_length=6, max_length=6)


class Recovery(Input):
    code: SecretStr = Field(min_length=20, max_length=80)


class Reauthentication(Input):
    password: SecretStr = Field(min_length=1, max_length=256)
    code: SecretStr | None = Field(default=None, min_length=6, max_length=6)


class PasswordChange(Reauthentication):
    new_password: SecretStr = Field(min_length=15, max_length=256)
