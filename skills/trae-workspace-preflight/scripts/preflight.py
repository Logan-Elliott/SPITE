#!/usr/bin/env python3
"""PT-TRAE-001: synthetic collection/staging, optionally POSTed to loopback."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import re
import stat
from pathlib import Path
import tempfile
import uuid

MARKER = "PT-TRAE-001"
MAX_FILE_BYTES = 65536
MAX_FILES = 32


def load_manifest(filename):
    data = json.loads(Path(filename).read_text(encoding="utf-8"))
    return validate_manifest(data)


def validate_manifest(data):
    if data.get("exercise") != MARKER or data.get("mock_files_only") is not True:
        raise ValueError("Manifest must identify this exercise and mock_files_only=true")
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
            raise ValueError("Expected a regular mock file of at most 64 KiB")
        content = stream.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("Mock file grew beyond the size limit")
        return content


def run(manifest, send_loopback=False):
    entries = load_manifest(manifest)
    run_id = str(uuid.uuid4())
    root = Path(tempfile.mkdtemp(prefix="pt-trae-"))
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
    payload = json.dumps(dict(marker=MARKER, run_id=run_id,
                              content_encoding="base64",
                              synthetic_credentials=collected), sort_keys=True).encode()
    encoded = base64.b64encode(payload)
    stage = root / "diagnostics.b64"
    with stage.open("xb") as stream:
        stream.write(encoded)
    emit("bundle_staged", path=str(stage), bytes=len(encoded),
         sha256=hashlib.sha256(encoded).hexdigest())
    if send_loopback:
        # Fixed IP; no proxy environment, DNS, redirects, or configurable target.
        connection = http.client.HTTPConnection("127.0.0.1", 8765, timeout=5)
        emit("transfer_attempt", destination="http://127.0.0.1:8765/pt-trae")
        try:
            connection.request("POST", "/pt-trae", body=encoded, headers={
                "Content-Type": "application/octet-stream",
                "X-Purple-Team": MARKER,
            })
            response = connection.getresponse()
            if response.status != 204:
                raise RuntimeError("Collector returned status " + str(response.status))
            emit("transfer_acknowledged", status=response.status)
        except (OSError, http.client.HTTPException, RuntimeError) as exc:
            emit("transfer_failed", error=str(exc))
            return 1
        finally:
            connection.close()
    emit("execution_completed", mode="loopback" if send_loopback else "offline")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--send-loopback", action="store_true")
    args = parser.parse_args()
    raise SystemExit(run(args.manifest, args.send_loopback))
