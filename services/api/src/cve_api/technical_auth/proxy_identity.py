"Exact technical host and private ingress capability precede certificate interpretation."

import hmac
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit
from uuid import UUID

from fastapi import Request

from cve_api.inventories.errors import UploadError
from cve_api.inventories.settings import InventorySettings

from .certificates import crl, fingerprint, leaf


@dataclass(frozen=True)
class TechnicalProof:
    token_id: UUID
    secret: str = field(repr=False)
    fingerprint: bytes
    ip: str


def proof(request: Request, settings: InventorySettings, gateway: str) -> TechnicalProof:
    expected = urlsplit(settings.origin)
    if request.headers.getlist("host") not in [
        [expected.netloc],
        [expected.hostname],
    ] or request.headers.getlist("x-cve-inventory-scheme") != ["https"]:
        raise UploadError(403, "untrusted_ingress")
    gate = request.headers.getlist("x-cve-inventory-gateway")
    if len(gate) != 1 or not hmac.compare_digest(gate[0], gateway):
        raise UploadError(403, "untrusted_ingress")
    if request.headers.getlist("x-cve-inventory-verify") != ["SUCCESS"]:
        raise UploadError(401, "mtls_required")
    if request.headers.get("cookie") or request.headers.get("origin"):
        raise UploadError(403, "identity_mixing")
    certificates = request.headers.getlist("x-cve-inventory-certificate")
    if len(certificates) != 1 or len(certificates[0]) > 16384:
        raise UploadError(401, "mtls_required")
    try:
        cert = leaf(unquote(certificates[0], errors="strict"))
        revoked = crl(settings.client_crl_file, settings.client_ca_file)
        if cert.issuer != revoked.issuer or revoked.get_revoked_certificate_by_serial_number(
            cert.serial_number
        ):
            raise UploadError(401, "certificate_revoked")
        ips = request.headers.getlist("x-real-ip")
        if len(ips) != 1:
            raise ValueError
        ip = str(ipaddress.ip_address(ips[0]))
        auth = request.headers.getlist("authorization")
        if len(auth) != 1 or not re.fullmatch(r"Bearer [0-9a-f-]{36}\.[A-Za-z0-9_-]{43}", auth[0]):
            raise ValueError
        public, secret = auth[0][7:].split(".")
        return TechnicalProof(UUID(public), secret, fingerprint(cert), ip)
    except (ValueError, UnicodeError):
        raise UploadError(401, "invalid_credentials") from None
    except UploadError as error:
        if error.status == 503:
            raise
        raise UploadError(401, "invalid_certificate") from None
