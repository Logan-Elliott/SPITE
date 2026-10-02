#!/usr/bin/env python3
"""One-request localhost collector. Exits after a request or 60 seconds idle."""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(5)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/asrt" or not 0 < length <= 4 * 1024 * 1024:
                raise ValueError("Unexpected path or size")
            payload = json.loads(base64.b64decode(self.rfile.read(length), validate=True))
            if not isinstance(payload, dict) or payload.get("marker") != "ASRT-001":
                raise ValueError("Unexpected marker")
        except (ValueError, OSError):
            self.send_error(400)
            return
        print(json.dumps(dict(event="collector_received", **payload)), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    with HTTPServer(("127.0.0.1", 8765), Handler) as server:
        server.timeout = 60
        print("ASRT-001 collector ready on 127.0.0.1:8765", flush=True)
        server.handle_request()
