"""One-shot host delivery of native Envoy LDS after namespace guards are installed.

No additional daemon/container: the socket disappears when this start operation ends.
A restarted original Envoy therefore has no listeners until its operator releases it.
"""

import json
import os
import socket
import socketserver
import stat
import struct
import threading
import uuid
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import TracebackType
from typing import Any


class ListenerDiscovery:
    def __init__(self, directory: Path, listeners: list[dict[str, Any]]) -> None:
        self.path = directory / "listener-discovery.sock"
        self.ready = threading.Event()
        self.sent = threading.Event()
        self.stop = threading.Event()
        self.pid: int | None = None
        self.failure = "no HTTP request"
        self.payload = json.dumps(
            {
                "version_info": str(uuid.uuid4()),
                "resources": [
                    {"@type": "type.googleapis.com/envoy.config.listener.v3.Listener", **item}
                    for item in listeners
                ],
                "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
            }
        ).encode()

    def __enter__(self) -> "ListenerDiscovery":
        delivery = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                self.connection.settimeout(3)
                pid, uid, _ = struct.unpack(
                    "3i",
                    self.connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                    ),
                )
                size = int(self.headers.get("Content-Length", "0"))
                delivery.failure = f"peer pid={pid}, uid={uid}, path={self.path}, size={size}"
                if (
                    uid != 65532
                    or self.path != "/v3/discovery:listeners"
                    or not 0 < size <= 1048576
                ):
                    self.send_error(403)
                    return
                self.rfile.read(size)
                if not delivery.ready.wait(30) or pid != delivery.pid:
                    self.send_error(403)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(delivery.payload)))
                self.end_headers()
                self.wfile.write(delivery.payload)
                self.wfile.flush()
                delivery.sent.set()

        if self.path.exists():
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                raise ValueError("Listener discovery requires its own Unix socket")
            self.path.unlink()
        # /proc fd path avoids Linux's 108-byte socket path limit for long project names.
        descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.server = socketserver.UnixStreamServer(
                f"/proc/self/fd/{descriptor}/{self.path.name}", Handler
            )
        finally:
            os.close(descriptor)
        self.path.chmod(0o666)
        self.server.timeout = 0.2

        def serve() -> None:
            while not self.stop.is_set() and not self.sent.is_set():
                self.server.handle_request()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        return self

    def release(self, pid: int) -> None:
        self.pid = pid
        self.ready.set()
        if not self.sent.wait(15):
            raise ValueError("Original Envoy listener configuration failed: " + self.failure)

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop.set()
        self.ready.set()
        self.thread.join(timeout=4)
        self.server.server_close()
        self.path.unlink(missing_ok=True)
