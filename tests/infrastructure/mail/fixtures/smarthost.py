"""Isolated SMTP provider: TLS/AUTH/DATA, controlled failures; no real recipients."""

import base64
import importlib.util
import json
import socketserver
import ssl
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

spec = importlib.util.spec_from_file_location("base", "/fixture/base.py")
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

base.state.update({"mode": "ok", "messages": [], "sni": []})


def count(key: str) -> None:
    with base.lock:
        base.state["counters"][key] = base.state["counters"].get(key, 0) + 1


base.__dict__["count"] = count


def tls_context() -> ssl.SSLContext:
    mode = base.state["mode"]
    name = {"wrong_name": "wrong", "foreign_ca": "foreign", "expired": "expired"}.get(
        mode, "upstream"
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if mode == "tls11":
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.load_cert_chain("/fixture/" + name + ".crt", "/fixture/" + name + ".key")

    def sni(_socket: Any, name: str | None, _context: Any) -> None:
        base.state["sni"].append(name)

    context.set_servername_callback(sni)
    return context


class SMTP(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        base.count("connections")
        sock = self.request
        sock.settimeout(10)
        mode = base.state["mode"]
        if mode == "drop":
            return
        if mode == "no_banner":
            time.sleep(7)
            return
        sock.sendall(
            b"220 mail.allowed.test ESMTP fixture\r\n" if mode != "bad_banner" else b"not SMTP\r\n"
        )
        encrypted = False
        authenticated = False
        sender = ""
        recipients: list[str] = []
        while True:
            line = b""
            while not line.endswith(b"\n"):
                data = sock.recv(1)
                if not data:
                    return
                line += data
            command = line.decode(errors="replace").strip()
            upper = command.upper()
            if upper.startswith("EHLO"):
                if mode == "ehlo_timeout":
                    time.sleep(7)
                    return
                if not encrypted and mode != "no_starttls":
                    sock.sendall(b"250-fixture\r\n250 STARTTLS\r\n")
                else:
                    sock.sendall(b"250-fixture\r\n250 AUTH PLAIN LOGIN\r\n")
            elif upper.startswith("STARTTLS"):
                sock.sendall(b"220 ready\r\n")
                try:
                    sock = tls_context().wrap_socket(sock, server_side=True)
                    encrypted = True
                except ssl.SSLError:
                    return
                base.count("tls")
            elif upper.startswith("AUTH"):
                base.count("auth")
                if not encrypted:
                    base.count("auth_before_tls")
                    sock.sendall(b"538 TLS required\r\n")
                    continue
                fields = command.split()
                if len(fields) < 3:
                    sock.sendall(b"334 \r\n")
                    fields.append(sock.recv(4096).decode().strip())
                try:
                    decoded = base64.b64decode(fields[2]).decode().split("\0")
                except Exception:
                    decoded = []
                expected_user = Path("/fixture/smtp_username").read_text().strip()
                expected_password = Path("/fixture/smtp_password").read_text().strip()
                accounts_path = Path("/fixture/smtp-accounts.json")
                accounts = (
                    json.loads(accounts_path.read_text())
                    if accounts_path.exists()
                    else {expected_user: expected_password}
                )
                authenticated = (
                    len(decoded) == 3
                    and accounts.get(decoded[-2]) == decoded[-1]
                    and mode != "bad_auth"
                )
                if authenticated:
                    with base.lock:
                        base.state.setdefault("authenticated_users", []).append(decoded[-2])
                sock.sendall(
                    b"235 authenticated\r\n"
                    if authenticated
                    else b"535 authentication rejected\r\n"
                )
            elif upper.startswith("MAIL FROM:"):
                sender = command[10:].split(">")[0].strip("< ")
                recipients = []
                sock.sendall(
                    b"250 sender\r\n" if authenticated else b"530 authentication required\r\n"
                )
            elif upper.startswith("RCPT TO:"):
                recipient = command[8:].split(">")[0].strip("< ")
                if mode == "temp":
                    sock.sendall(b"450 temporary fixture failure\r\n")
                elif mode == "perm":
                    sock.sendall(
                        b"450 hold controlled bounce\r\n"
                        if not sender
                        else b"550 permanent fixture failure\r\n"
                    )
                else:
                    recipients.append(recipient)
                    sock.sendall(b"250 recipient\r\n")
            elif upper == "DATA":
                sock.sendall(b"354 data\r\n")
                body = b""
                while not body.endswith(b"\r\n.\r\n"):
                    data = sock.recv(4096)
                    if not data:
                        return
                    body += data
                if not authenticated:
                    return
                with base.lock:
                    base.state["messages"].append(
                        {
                            "sender": sender,
                            "recipients": recipients,
                            "body": body.decode(errors="replace"),
                        }
                    )
                base.count("accepted")
                if mode == "drop_after_data":
                    return
                sock.sendall(b"250 queued by isolated fixture\r\n")
            elif upper == "QUIT":
                sock.sendall(b"221 bye\r\n")
                return
            else:
                sock.sendall(b"250 OK\r\n")


if __name__ == "__main__":
    base.state["records"] = {"mail.allowed.test": ["A", "93.184.216.34"]}
    for server in (
        ThreadingHTTPServer(("0.0.0.0", 8080), base.HTTP),
        base.TCP(("0.0.0.0", 587), SMTP),
        socketserver.ThreadingUDPServer(("0.0.0.0", 53), base.DNS),
    ):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    Path("/tmp/fixture-ready").touch()
    threading.Event().wait()
