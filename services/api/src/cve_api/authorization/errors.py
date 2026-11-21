"""Generic client errors with internal, nonsecret decision categories."""

from cve_common.http.errors import ServiceError


class Denied(ServiceError):
    def __init__(self, status: int = 403, reason: str = "permission_denied") -> None:
        self.reason = reason
        super().__init__(status)
