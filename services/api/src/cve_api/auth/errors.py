"""Safe failures without account or credential details."""

from cve_common.http.errors import ServiceError


class AuthError(ServiceError):
    def __init__(self, status: int = 401) -> None:
        super().__init__(status)
