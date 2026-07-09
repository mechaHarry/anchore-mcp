"""Loopback-only synthetic HTTP server with connection/request accounting."""

from collections.abc import Generator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
from typing import cast

from pydantic import JsonValue


class SyntheticAnchoreServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, routes: Mapping[str, JsonValue]) -> None:
        self.routes = dict(routes)
        self.requests: list[str] = []
        self.connection_ids: list[int] = []
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def base_url(self) -> str:
        host, port = cast(tuple[str, int], self.server_address)
        return f"http://{host}:{port}"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        server = cast(SyntheticAnchoreServer, self.server)
        server.requests.append(self.path)
        server.connection_ids.append(id(self.connection))
        data = server.routes.get(self.path, {"error": "not found"})
        payload = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(200 if self.path in server.routes else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class SlowTlsHandshakeServer:
    """Accept one TCP connection and hold it before completing a TLS handshake."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._stop = threading.Event()
        self.connection_accepted = threading.Event()
        self._connection: socket.socket | None = None
        self._thread = threading.Thread(
            target=self._serve,
            name="synthetic-slow-tls",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        host, port = cast(tuple[str, int], self._listener.getsockname())
        return f"https://{host}:{port}"

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        try:
            connection, _address = self._listener.accept()
        except OSError:
            return
        self._connection = connection
        self.connection_accepted.set()
        try:
            self._stop.wait()
        finally:
            connection.close()

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        connection = self._connection
        if connection is not None:
            connection.close()
        self._thread.join(timeout=2)


@contextmanager
def synthetic_anchore_server(
    routes: Mapping[str, JsonValue],
) -> Generator[SyntheticAnchoreServer]:
    server = SyntheticAnchoreServer(routes)
    thread = threading.Thread(target=server.serve_forever, name="synthetic-anchore", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def slow_tls_handshake_server() -> Generator[SlowTlsHandshakeServer]:
    server = SlowTlsHandshakeServer()
    server.start()
    try:
        yield server
    finally:
        server.close()
