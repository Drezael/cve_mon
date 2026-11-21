"Public certificate verification rejects private material, expired/wrong-purpose/revoked leaves."

from pathlib import Path

import pytest
from cve_api.inventories.errors import UploadError
from cve_api.technical_auth.certificates import fingerprint, registered

from scripts.infrastructure.manage import generate_certificates, load_config
from scripts.inventory.configuration import development_crl


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("upload-pki") / "pki"
    cfg = load_config(
        overrides={"TLS_DIR": str(base), "SECRETS_BASE": str(base.parent / "secrets")},
    )
    generate_certificates(cfg, fixtures=True)
    development_crl(cfg)
    return base


def test_sha256_binding_and_new_certificate(pki: Path) -> None:
    a = registered(
        (pki / "client.crt").read_text(), "", pki / "client-ca.crt", pki / "client-ca.crl"
    )
    b = registered(
        (pki / "client-new.crt").read_text(), "", pki / "client-ca.crt", pki / "client-ca.crl"
    )
    assert len(fingerprint(a)) == 32 and fingerprint(a) != fingerprint(b)


@pytest.mark.parametrize(
    "name", ["untrusted-client", "expired-client", "revoked-client", "wrong-purpose-client"]
)
def test_invalid_leaves(pki: Path, name: str) -> None:
    with pytest.raises(UploadError):
        registered(
            (pki / (name + ".crt")).read_text(), "", pki / "client-ca.crt", pki / "client-ca.crl"
        )


def test_appended_private_key_is_never_accepted(pki: Path) -> None:
    value = (pki / "client.crt").read_text() + (pki / "client.key").read_text()
    with pytest.raises(UploadError):
        registered(value, "", pki / "client-ca.crt", pki / "client-ca.crl")
