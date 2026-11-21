"Public certificate chain/EKU/CRL checks and SHA-256 binding; private keys are never accepted."

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from cve_api.inventories.errors import UploadError


def leaf(pem: str) -> x509.Certificate:
    if (
        not pem.isascii()
        or len(pem) > 8192
        or not re.fullmatch(
            r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", pem.strip()
        )
    ):
        raise UploadError(422, "certificate_format")
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        now = datetime.now(UTC)
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if (
            basic.ca
            or ExtendedKeyUsageOID.CLIENT_AUTH not in usage
            or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc
        ):
            raise ValueError("Unusable client certificate")
        return cert
    except (ValueError, UnicodeError, x509.ExtensionNotFound):
        raise UploadError(422, "certificate_invalid") from None


def crl(path: Path, ca_file: Path) -> x509.CertificateRevocationList:
    try:
        value = x509.load_pem_x509_crl(path.read_bytes())
        roots = x509.load_pem_x509_certificates(ca_file.read_bytes())
        now = datetime.now(UTC)
        if (
            value.next_update_utc is None
            or not value.last_update_utc <= now < value.next_update_utc
        ):
            raise ValueError("CRL expired")
        if not any(
            value.issuer == root.subject
            and root.not_valid_before_utc <= now < root.not_valid_after_utc
            and value.is_signature_valid(cast(CertificateIssuerPublicKeyTypes, root.public_key()))
            for root in roots
        ):
            raise ValueError("Invalid CRL signature")
        return value
    except (ValueError, OSError, TypeError):
        raise UploadError(503, "pki_unavailable") from None


def registered(pem: str, chain: str, ca_file: Path, crl_file: Path) -> x509.Certificate:
    cert = leaf(pem)
    if "PRIVATE KEY" in chain:
        raise UploadError(422, "private_key_forbidden")
    try:
        roots = x509.load_pem_x509_certificates(ca_file.read_bytes())
        intermediates = x509.load_pem_x509_certificates(chain.encode()) if chain else []
        if len(intermediates) > 2:
            raise ValueError("Chain too long")
        PolicyBuilder().store(Store(roots)).max_chain_depth(2).build_client_verifier().verify(
            cert, intermediates
        )
        revoked = crl(crl_file, ca_file)
        if cert.issuer != revoked.issuer:
            raise ValueError("Issuing CA needs its own CRL")
        if revoked.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            raise ValueError("Certificate revoked")
    except (VerificationError, ValueError, OSError):
        raise UploadError(422, "certificate_untrusted") from None
    return cert


def fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())
