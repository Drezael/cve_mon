"""Stable error categories contain no exception text or credentials."""

import asyncio
import errno
import re
import socket
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from enum import StrEnum

import httpx
from pydantic import ValidationError
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeout


class ErrorCode(StrEnum):
    TEMPORARY = "TEMPORARY"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNKNOWN_JOB = "UNKNOWN_JOB"
    FORBIDDEN = "FORBIDDEN"
    PERMANENT = "PERMANENT"
    LEASE_LOST = "LEASE_LOST"
    CANCELLED = "CANCELLED"
    SHUTDOWN = "SHUTDOWN"


class JobError(Exception):
    def __init__(
        self, code: ErrorCode = ErrorCode.PERMANENT, *, diagnostic_code: str | None = None
    ) -> None:
        if diagnostic_code is not None and not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,63}", diagnostic_code
        ):
            raise ValueError("Invalid diagnostic code")
        self.code = code
        self.diagnostic_code = diagnostic_code
        super().__init__(code.value)


class LeaseLost(JobError):
    def __init__(self) -> None:
        super().__init__(ErrorCode.LEASE_LOST)


class IdempotencyConflict(ValueError):
    """A key already names a different request; no payload in diagnostics."""


@dataclass(frozen=True)
class Failure:
    code: ErrorCode
    retry: bool


def classify(error: BaseException) -> Failure:
    if isinstance(error, JobError):
        return Failure(
            error.code,
            error.code
            in {
                ErrorCode.TEMPORARY,
                ErrorCode.NETWORK,
                ErrorCode.DATABASE,
                ErrorCode.RATE_LIMIT,
                ErrorCode.UNAVAILABLE,
            },
        )
    if isinstance(error, BrokenProcessPool):
        return Failure(ErrorCode.UNAVAILABLE, True)
    if isinstance(error, (asyncio.TimeoutError, httpx.TimeoutException)):
        return Failure(ErrorCode.TIMEOUT, True)
    if isinstance(error, (httpx.NetworkError, httpx.ProxyError, httpx.RemoteProtocolError)):
        return Failure(ErrorCode.NETWORK, True)
    if isinstance(error, (ConnectionError, socket.gaierror)) or (
        isinstance(error, OSError)
        and error.errno
        in {
            errno.ENETDOWN,
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ECONNRESET,
            errno.ECONNREFUSED,
            errno.ECONNABORTED,
            errno.ENOTCONN,
            errno.EPIPE,
        }
    ):
        return Failure(ErrorCode.NETWORK, True)
    if isinstance(error, PoolTimeout):
        return Failure(ErrorCode.DATABASE, True)
    if isinstance(error, DBAPIError):
        sqlstate = getattr(error.orig, "sqlstate", "") or ""
        if sqlstate.startswith(("08", "40", "53", "57")):
            return Failure(ErrorCode.DATABASE, True)
        return Failure(ErrorCode.PERMANENT, False)
    if isinstance(error, ValidationError):
        return Failure(ErrorCode.INVALID_PAYLOAD, False)
    if isinstance(error, PermissionError):
        return Failure(ErrorCode.FORBIDDEN, False)
    return Failure(ErrorCode.PERMANENT, False)
