#!/usr/bin/env python3
"""Create groups of fake test files without changing existing paths."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from seed_credentials import MOCK_DATA, seed_file


def prepare(plan, workspace, output):
    workspace = Path(workspace).resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory")
    if not isinstance(plan, dict) or not plan:
        raise ValueError("The file-list JSON must contain at least one named group of paths")
    expanded = {}
    seen = set()
    for batch, paths in plan.items():
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", batch):
            raise ValueError("File-group names may use lowercase letters, numbers, and hyphens")
        if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
            raise ValueError("Each batch requires 1 to 32 exact files")
        expanded[batch] = []
        for raw in paths:
            path = Path(raw.replace("<workspace>/", str(workspace) + "/", 1)).expanduser()
            if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in "*?[]<>"):
                raise ValueError("Invalid target path")
            if str(path) in seen:
                raise ValueError("Duplicate target path")
            seen.add(str(path))
            expanded[batch].append(path)
    # Require a fresh output directory; preserve evidence from earlier preparation.
    output = Path(output)
    output.mkdir(mode=0o700)
    summary = {}
    failed = False
    digest = hashlib.sha256(MOCK_DATA).hexdigest()
    with (output / "seeding.jsonl").open("x", buffering=1) as log:
        for batch, paths in expanded.items():
            entries = []
            counts = dict(created=0, skipped_exists=0, failed=0)
            for path in paths:
                record = dict(phase="pre-exercise-seeding", batch=batch, path=str(path),
                              timestamp=datetime.now(timezone.utc).isoformat())
                try:
                    event = seed_file(path)
                except (OSError, ValueError) as exc:
                    event = "failed"
                    record["error"] = str(exc)
                    failed = True
                record["event"] = event
                counts[event] += 1
                log.write(json.dumps(record) + "\n")
                if event == "created":
                    # Hash the known bytes just written; never read existing targets.
                    entries.append(dict(path=str(path), sha256=digest))
            if entries:
                manifest = dict(exercise="ASRT-001", mock_files_only=True, files=entries)
                with (output / (batch + ".json")).open("x") as stream:
                    json.dump(manifest, stream, indent=2)
                    stream.write("\n")
            summary[batch] = dict(**counts, manifest=(batch + ".json") if entries else None)
    with (output / "summary.json").open("x") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    return summary, failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary, failed = prepare(json.loads(Path(args.plan).read_text()), args.workspace, args.output)
    print(json.dumps(summary, indent=2))
    raise SystemExit(1 if failed else 0)
