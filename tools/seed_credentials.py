#!/usr/bin/env python3
"""Create fake credential files at exact paths without replacing existing entries."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

MOCK_DATA = b"# ASRT-001 synthetic exercise data; not a usable credential\nASRT_MOCK_TOKEN=NOT-A-REAL-SECRET\n"


def seed_file(path):
    """Return created/skipped_exists; traverse parents without following links."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in "*?[]<>"):
        raise ValueError("Provide an exact absolute path without globs or '..'")
    # Check first, including dangling symlinks, without reading existing content.
    if os.path.lexists(path):
        return "skipped_exists"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:-1]:
            try:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        # Atomic exclusivity also protects against creation after the first check.
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
        except FileExistsError:
            return "skipped_exists"
        with os.fdopen(fd, "wb") as stream:
            stream.write(MOCK_DATA)
            stream.flush()
            os.fsync(stream.fileno())
        return "created"
    finally:
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", required=True,
                        help="Exact target file; repeat as needed. No directory scans.")
    args = parser.parse_args()
    failed = False
    for name in args.file:
        path = Path(name).expanduser()
        record = dict(phase="pre-exercise-seeding", path=str(path),
                      timestamp=datetime.now(timezone.utc).isoformat())
        try:
            record["event"] = seed_file(path)
        except (OSError, ValueError) as exc:
            record.update(event="failed", error=str(exc))
            failed = True
        print(json.dumps(record), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
