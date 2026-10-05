#!/usr/bin/env python3
"""One-request localhost receiver. Exits after a request or 60 seconds idle."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(5)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/spite" or length <= 0:
                raise ValueError("Unexpected path or empty body")
            body = self.rfile.read(length)
            payload = json.loads(base64.b64decode(body, validate=True))
            if not isinstance(payload, dict) or payload.get("marker") != "SPITE-001":
                raise ValueError("Unexpected marker")
        except (ValueError, OSError):
            self.send_error(400)
            return
        print(json.dumps(dict(event="collector_received", **payload)), flush=True)
        self.send_response(204)
        self.send_header("X-SPITE-Receipt", hashlib.sha256(body).hexdigest())
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    with HTTPServer(("127.0.0.1", 8765), Handler) as server:
        server.timeout = 60
        print("HTTP receiver READY: 127.0.0.1:8765; one request", flush=True)
        server.handle_request()
