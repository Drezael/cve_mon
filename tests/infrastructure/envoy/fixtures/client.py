"""Transparenter HTTP-/CONNECT-/STARTTLS-Testclient mit immer aktiver TLS-Prüfung."""

import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

request = json.load(sys.stdin)
result: dict[str, Any] = {}
try:
    kind = request["kind"]
    host, port = request.get("proxy_host", "cve-egress-proxy"), request.get("proxy_port", 3128)
    if kind == "http":
        target = request["target"]
        connection = http.client.HTTPConnection(host, port, timeout=3)
        connection.request(
            request.get("method", "GET"),
            target,
            body=request.get("body"),
            headers=request.get("headers", {}),
        )
        response = connection.getresponse()
        result = {
            "status": response.status,
            "body": response.read().decode(errors="replace"),
            "location": response.getheader("location"),
        }
    elif kind == "https":
        connection = http.client.HTTPSConnection(
            host, port, timeout=3, context=ssl.create_default_context(cafile="/fixture/server.crt")
        )
        connection.set_tunnel(
            request["target"], request.get("target_port", 443), headers=request.get("headers", {})
        )
        connection.request("GET", request.get("path", "/"))
        response = connection.getresponse()
        result = {"status": response.status, "body": response.read().decode()}
    elif kind == "smtp":
        with socket.create_connection((host, 1587), timeout=3) as smtp_socket:
            banner = smtp_socket.recv(4096).decode()
            result = {"banner": banner}
            smtp_socket.sendall(b"EHLO test\r\n")
            result["ehlo"] = smtp_socket.recv(4096).decode()
            if request.get("starttls", False):
                smtp_socket.sendall(b"STARTTLS\r\n")
                result["starttls"] = smtp_socket.recv(4096).decode()
                context = ssl.create_default_context(cafile="/fixture/server.crt")
                with context.wrap_socket(
                    smtp_socket, server_hostname=request.get("verify_host", "mail.allowed.test")
                ) as tls:
                    tls.sendall(b"QUIT\r\n")
                    result["quit"] = tls.recv(4096).decode()
    elif kind == "raw":
        with socket.create_connection((host, port), timeout=2) as raw_socket:
            raw_socket.sendall(request["data"].encode())
            result = {"data": raw_socket.recv(8192).decode(errors="replace")}
    elif kind == "direct":
        with socket.create_connection((request["target"], request["target_port"]), timeout=1):
            result = {"connected": True}
    elif kind == "hold":
        sockets = []
        rejected = 0
        try:
            for _ in range(70):
                try:
                    sock = socket.create_connection((host, port), timeout=0.5)
                    sock.sendall(b"GET ")
                    sockets.append(sock)
                except OSError:
                    rejected += 1
            time.sleep(0.1)
            for sock in sockets:
                sock.settimeout(0.02)
                try:
                    if not sock.recv(1):
                        rejected += 1
                except TimeoutError:
                    pass
                except OSError:
                    rejected += 1
            result = {"rejected": rejected}
        finally:
            for sock in sockets:
                sock.close()
    elif kind == "variables":
        proxy = os.environ.get(
            "HTTPS_PROXY" if request["target"].startswith("https") else "HTTP_PROXY"
        )
        if not proxy:
            raise ValueError("proxy configuration required")
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        tls_handler = urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile="/fixture/server.crt")
        )
        opener = urllib.request.build_opener(handler, tls_handler)
        with opener.open(request["target"], timeout=3) as response:
            result = {"status": response.status, "body": response.read().decode()}
except Exception as error:
    result = {"error": type(error).__name__, "detail": str(error)[:300]}
print(json.dumps(result))
