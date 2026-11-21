"""Single certificate input folder; internal client CA/CRL are managed automatically."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.infrastructure.manage import Config


def prepare(config: Config) -> None:
    from scripts.infrastructure.manage import generate_certificates
    from scripts.infrastructure.mounts import checked, ensure_directory
    from scripts.infrastructure.storage import helper
    from scripts.inventory.configuration import development_crl

    folder = Path(config.values["TLS_DIR"])
    if config.values["APP_ENV"] == "production":
        # Mount the Certbot root at its original path, preserving live/../archive links.
        source = folder.parent.parent if folder.parent.name == "live" else folder
        staging = config.secrets_base / "tls-input" / config.project
        ensure_directory(config, staging.parent)
        ensure_directory(config, staging)
        try:
            helper(
                config,
                [
                    "type=bind,source=" + str(source) + ",target=" + str(source) + ",readonly",
                    "type=bind,source=" + str(staging) + ",target=/target",
                ],
                f"test -s {folder}/fullchain.pem; test -s {folder}/privkey.pem; "
                f"cp -L {folder}/fullchain.pem /target/fullchain.pem; "
                f"cp -L {folder}/privkey.pem /target/privkey.pem; "
                f"if test -f {folder}/ca.crt; then cp -L {folder}/ca.crt /target/ca.crt; "
                "else rm -f /target/ca.crt; fi; "
                f"chown {config.values['NGINX_UID']}:{config.values['NGINX_GID']} /target/*; "
                "chmod 600 /target/*",
            )
        except subprocess.CalledProcessError:
            raise ValueError(
                "TLS_DIR: fullchain.pem und privkey.pem konnten nicht eingelesen werden"
            ) from None
        config.values["TLS_CERT_FILE"] = str(staging / "fullchain.pem")
        config.values["TLS_KEY_FILE"] = str(staging / "privkey.pem")
        if (staging / "ca.crt").is_file():
            config.values["TLS_TRUST_FILE"] = str(staging / "ca.crt")
    else:
        checked(folder)
        cert = Path(config.values["TLS_CERT_FILE"])
        key = Path(config.values["TLS_KEY_FILE"])
        if not cert.is_file() or not key.is_file():
            if cert.exists() or key.exists():
                raise ValueError(
                    "TLS_DIR ist unvollständig: fullchain.pem und privkey.pem werden benötigt"
                )
            generate_certificates(config)
    ca = Path(config.values["CLIENT_CA_FILE"])
    ensure_directory(config, ca.parent.parent)
    ensure_directory(config, ca.parent)
    signing = ca.with_suffix(".key")
    if not ca.exists():
        if signing.exists():
            raise ValueError(
                "Vorhandener Client-CA-Schlüssel hat kein Zertifikat; kein Ersatz erzeugt"
            )
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CVE Internal Client CA")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private, hashes.SHA256())
        )
        for target, payload in [
            (
                signing,
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            ),
            (ca, certificate.public_bytes(serialization.Encoding.PEM)),
        ]:
            with target.open("xb") as stream:
                target.chmod(0o600)
                stream.write(payload)
        (ca.parent / "managed-client-ca.json").write_text('{"managed": true}\n')
    development_crl(config)


def refresh(config: Config) -> bool:
    """Validate renewed input before replacing the active certificate and reloading Nginx."""
    import shutil
    import tempfile
    from dataclasses import replace

    from scripts.infrastructure.manage import certificate_preflight, compose

    candidate = replace(config, values=dict(config.values))
    certificate_preflight(candidate)
    active = config.directory / "tls"
    files = {
        "server.crt": "TLS_CERT_FILE",
        "server.key": "TLS_KEY_FILE",
        "client-ca.crt": "CLIENT_CA_FILE",
        "client-ca.crl": "CLIENT_CRL_FILE",
    }
    if not active.is_dir():
        return False
    if all(
        (active / name).is_file()
        and (active / name).read_bytes() == Path(candidate.values[key]).read_bytes()
        for name, key in files.items()
    ):
        return False
    with tempfile.TemporaryDirectory(prefix="tls-previous-", dir=config.directory) as temporary:
        backup = Path(temporary)
        for name in files:
            shutil.copy2(active / name, backup / name)
        try:
            for name, key in files.items():
                pending = active / (name + ".new")
                pending.write_bytes(Path(candidate.values[key]).read_bytes())
                pending.chmod(0o600)
                pending.replace(active / name)
            from scripts.inventory.configuration import trust

            trust(candidate, config.secrets_base / "services" / config.project)
            compose(config, ["exec", "-T", "cve-nginx", "nginx", "-t"])
            compose(config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
        except Exception:
            for name in files:
                (backup / name).replace(active / name)
            raise
    return True
