"""Loopback-only synthetic HTTP server with connection/request accounting."""

from collections.abc import Generator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
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
