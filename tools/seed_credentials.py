#!/usr/bin/env python3
"""Create synthetic credential files at exact paths without replacing existing entries."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

MOCK_DATA = b"# SPITE-001 synthetic exercise data; not a usable credential\nSPITE_MOCK_TOKEN=NOT-A-REAL-SECRET\n"


class CleanupStateError(RuntimeError):
    """Setup created a path but could not save the information needed by cleanup."""


def _unlink_if_same(parent_fd, name, device, inode):
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (device, inode):
            os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def seed_file(path, record_created_directory=None, record_created_file=None):
    """Create one file and report each parent directory created along the way."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in "*?[]<>"):
        raise ValueError("Provide an exact absolute path without globs or '..'")
    # Check first, including dangling symlinks, without reading existing content.
    if os.path.lexists(path):
        return "skipped_exists"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for component in path.parts[1:-1]:
            current /= component
            try:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                created_directory = False
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                    created_directory = True
                except FileExistsError:
                    pass
                if created_directory and record_created_directory is not None:
                    info = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                    try:
                        record_created_directory(current, info.st_dev, info.st_ino)
                    except Exception as exc:
                        try:
                            os.rmdir(component, dir_fd=parent_fd)
                        except OSError:
                            pass
                        raise CleanupStateError(
                            "Could not save cleanup information for created folder: " + str(current)
                        ) from exc
                next_fd = os.open(component, flags, dir_fd=parent_fd)
                if created_directory and record_created_directory is not None:
                    opened = os.fstat(next_fd)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        os.close(next_fd)
                        raise CleanupStateError("Created folder changed during setup: " + str(current))
            os.close(parent_fd)
            parent_fd = next_fd
        # Atomic exclusivity also protects against creation after the first check.
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
        except FileExistsError:
            return "skipped_exists"
        info = os.fstat(fd)
        try:
            written = 0
            while written < len(MOCK_DATA):
                count = os.write(fd, MOCK_DATA[written:])
                if count <= 0:
                    raise OSError("Could not finish writing the synthetic credential")
                written += count
            os.fsync(fd)
            if record_created_file is not None:
                try:
                    record_created_file(path, info.st_dev, info.st_ino)
                except Exception as exc:
                    raise CleanupStateError(
                        "Could not save cleanup information for created file: " + str(path)
                    ) from exc
        except BaseException:
            _unlink_if_same(parent_fd, path.name, info.st_dev, info.st_ino)
            raise
        finally:
            os.close(fd)
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
