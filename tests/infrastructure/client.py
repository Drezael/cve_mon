"""TLS-Testclient mit echter CA-/Hostnameprüfung und explizitem SNI."""

import http.client
import socket
import ssl
from dataclasses import dataclass

from scripts.infrastructure.manage import Config


@dataclass
class Response:
    """Bewahre auch Headernamen zum Erkennen von Duplikaten."""

    status: int
    headers: dict[str, str]
    header_names: list[str]
    body: str


def request(
    config: Config,
    domain: str = "dashboard.example.test",
    path: str = "/",
    method: str = "GET",
    client: str | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    tls: bool = True,
    version: ssl.TLSVersion | None = None,
    timeout: float = 5,
) -> Response:
    """Verbinde Loopback, verifiziere aber den tatsächlichen Domainnamen."""
    port = int(config.values["INGRESS_HTTPS_PORT" if tls else "INGRESS_HTTP_PORT"])
    from tests.inventory_upload.integration.technical_gateway import GATEWAYS

    internal = GATEWAYS.get(config.project) if domain == "inventory.internal" else None
    address = internal["address"] if internal else "127.0.0.1"
    if internal:
        port = internal["port"]
    connection = http.client.HTTPConnection(address, port, timeout=timeout)
    if tls:
        context = ssl.create_default_context(
            cafile=str(internal["ca_file"]) if internal else config.values["TLS_TRUST_FILE"]
        )
        if version is not None:
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers("ALL:@SECLEVEL=0")
        if client:
            directory = config.values["TLS_CERT_FILE"].rsplit("/", 1)[0]
            context.load_cert_chain(
                directory + "/" + client + ".crt", directory + "/" + client + ".key"
            )
        connection.sock = context.wrap_socket(
            socket.create_connection((address, port), timeout=timeout), server_hostname=domain
        )
    try:
        connection.request(method, path, body, {"Host": domain, **(headers or {})})
        response = connection.getresponse()
        pairs = response.getheaders()
        return Response(
            response.status,
            {k.lower(): v for k, v in pairs},
            [k.lower() for k, _ in pairs],
            response.read().decode(),
        )
    finally:
        connection.close()
