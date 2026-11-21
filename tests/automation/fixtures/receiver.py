"""Isolated HTTPS receiver with auth, controlled errors and uncertain acknowledgements."""

import json
import socket
import ssl
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

state: dict[str, Any] = {"mode": "ok", "messages": [], "auth_failures": 0}
lock = threading.Lock()


class TLSHTTP(ThreadingHTTPServer):
    def get_request(self) -> tuple[socket.socket, Any]:
        client, peer = super().get_request()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        name = "wrong" if state["mode"] == "wrong_tls" else "server"
        context.load_cert_chain("/fixture/" + name + ".crt", "/fixture/" + name + ".key")
        try:
            return context.wrap_socket(client, server_side=True), peer
        except ssl.SSLError:
            client.close()
            raise


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def reply(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(data)

    def do_GET(self) -> None:
        with lock:
            self.reply(200, state)

    def do_POST(self) -> None:
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/control":
            with lock:
                state.update(json.loads(data))
            self.reply(200, {})
            return
        expected = "Bearer " + Path("/fixture/auth_token").read_text().strip()
        if self.headers.get("Authorization") != expected or state["mode"] == "bad_auth":
            with lock:
                state["auth_failures"] += 1
            self.reply(401, {})
            return
        mode = state["mode"]
        if mode == "temp":
            self.reply(503, {})
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://169.254.169.254/forbidden")
            self.end_headers()
            return
        if mode == "perm":
            self.reply(400, {})
            return
        if mode == "slow":
            time.sleep(1)
        event = json.loads(data)
        with lock:
            state["messages"].append(
                {"event_id": event["event_id"], "idempotency": self.headers.get("Idempotency-Key")}
            )
        if mode == "drop_after_accept":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.reply(200, {"accepted": True})


for server in (
    TLSHTTP(("0.0.0.0", 8443), Receiver),
    ThreadingHTTPServer(("127.0.0.1", 8080), Receiver),
):
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
