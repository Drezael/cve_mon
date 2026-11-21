"""Nur isolierte Phase-4-Tests: kontrollierte DNS-, HTTP-/TLS- und SMTP-Ziele."""

import collections
import json
import socket
import socketserver
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

lock = threading.Lock()
state: dict[str, Any] = {"records": {}, "counters": collections.Counter(), "smtp_hang": False}


def count(key: str) -> None:
    with lock:
        state["counters"][key] += 1


def context() -> ssl.SSLContext:
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    result.load_cert_chain("/fixture/server.crt", "/fixture/server.key")
    return result


class HTTP(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        count("http_request")
        if self.path == "/control":
            with lock:
                payload = json.dumps(state).encode()
            self.send_response(200)
        else:
            payload = b"controlled-egress-target"
            self.send_response(302 if self.path.startswith("/redirect") else 200)
            if self.path.startswith("/redirect"):
                self.send_header("Location", "http://forbidden.example.test/blocked")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/control":
            with lock:
                state.update(json.loads(body))
            self.send_response(204)
            self.end_headers()
        else:
            self.do_GET()

    def log_message(self, *_args: Any) -> None:
        pass


class CountHTTP(ThreadingHTTPServer):
    def get_request(self) -> tuple[socket.socket, Any]:
        client, peer = super().get_request()
        count("tcp_" + str(self.server_port))
        return client, peer


class TLSHTTP(CountHTTP):
    def get_request(self) -> tuple[socket.socket, Any]:
        client, peer = super().get_request()
        try:
            return context().wrap_socket(client, server_side=True), peer
        except ssl.SSLError:
            client.close()
            raise


class SMTP(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        count("tcp_587")
        client = self.request
        client.settimeout(4)
        if state["smtp_hang"]:
            time.sleep(4)
            return
        client.sendall(b"220 mail.allowed.test ESMTP fixture\r\n")
        while True:
            line = b""
            while not line.endswith(b"\n"):
                data = client.recv(1)
                if not data:
                    return
                line += data
            if line.upper().startswith(b"EHLO"):
                client.sendall(b"250-mail.allowed.test\r\n250-STARTTLS\r\n250 OK\r\n")
            elif line.upper().startswith(b"STARTTLS"):
                client.sendall(b"220 ready for TLS\r\n")
                try:
                    client = context().wrap_socket(client, server_side=True)
                except ssl.SSLError:
                    return
            elif line.upper().startswith(b"QUIT"):
                client.sendall(b"221 bye\r\n")
                return
            else:
                client.sendall(b"250 fixture response\r\n")


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def dns_response(data: bytes) -> bytes:
    offset = 12
    parts = []
    while data[offset]:
        length = data[offset]
        parts.append(data[offset + 1 : offset + length + 1].decode())
        offset += length + 1
    offset += 1
    qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
    question = data[12 : offset + 4]
    domain = ".".join(parts)
    count("dns_" + domain + "_" + str(qtype))
    with lock:
        record = state["records"].get(domain)
    answers = []
    if record:
        kind, target = record
        if kind == "CNAME":
            encoded = b"".join(bytes([len(s)]) + s.encode() for s in target.split(".")) + b"\0"
            answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 1, len(encoded)) + encoded)
            # Private CNAME-Adresse auch in derselben Antwort anbieten.
            addr = socket.inet_aton(state["records"].get(target, ["A", "127.0.0.1"])[1])
            answers.append(encoded + struct.pack("!HHIH", 1, 1, 1, 4) + addr)
        elif kind in ("A", "DUAL") and qtype == 1:
            answers.append(
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 1, 4)
                + socket.inet_aton("93.184.216.34" if kind == "DUAL" else target)
            )
        elif kind in ("AAAA", "DUAL") and qtype == 28:
            answers.append(
                b"\xc0\x0c"
                + struct.pack("!HHIH", 28, 1, 1, 16)
                + socket.inet_pton(socket.AF_INET6, target)
            )
    flags = 0x8180 if record else 0x8183
    return (
        data[:2]
        + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
        + question
        + b"".join(answers)
    )


class DNS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(dns_response(data), self.client_address)


if __name__ == "__main__":
    with lock:
        state["records"] = {
            name: ["A", "93.184.216.34"]
            for name in (
                "http.allowed.test",
                "tls.allowed.test",
                "mail.allowed.test",
                "rebind.allowed.test",
                "cname.allowed.test",
                "ipv6.allowed.test",
                "alternate.allowed.test",
            )
        }
    servers = [
        CountHTTP(("0.0.0.0", 80), HTTP),
        TLSHTTP(("0.0.0.0", 443), HTTP),
        ThreadingHTTPServer(("0.0.0.0", 8080), HTTP),
        TCP(("0.0.0.0", 587), SMTP),
        socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNS),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    Path("/tmp/fixture-ready").touch()
    threading.Event().wait()
