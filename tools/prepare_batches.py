#!/usr/bin/env python3
"""Create groups of fake test files or select existing real files without changing them."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re

from seed_credentials import MOCK_DATA, seed_file
import profile_paths


def load_runner():
    script = Path(__file__).resolve().parents[1] / "skills/agent-workspace-preflight/scripts/preflight.py"
    spec = importlib.util.spec_from_file_location("prepare_preflight", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(plan, workspace, output, source="synthetic", record_created=None,
            record_created_directory=None):
    if source not in ("synthetic", "real"):
        raise ValueError("Harvest source must be synthetic or real")
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
            path = profile_paths.resolve(raw, workspace, source)
            if path is not None:
                if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in "*?[]<>"):
                    raise ValueError("Invalid target path")
                if str(path) in seen:
                    raise ValueError("Duplicate target path")
                seen.add(str(path))
            expanded[batch].append((raw, path))
    # Require a fresh output directory; preserve evidence from earlier preparation.
    output = Path(output)
    output.mkdir(mode=0o700)
    summary = {}
    failed = False
    runner = load_runner() if source == "real" else None
    with (output / ("selection.jsonl" if source == "real" else "seeding.jsonl")).open("x", buffering=1) as log:
        for batch, targets in expanded.items():
            entries = []
            if source == "real":
                counts = dict(collected=0, missing=0, unusable=0, unresolved=0)
                for raw, path in targets:
                    record = dict(phase="pre-exercise-selection", batch=batch,
                                  path=str(path) if path is not None else raw,
                                  timestamp=datetime.now(timezone.utc).isoformat())
                    if path is None:
                        event = "unresolved"
                    else:
                        try:
                            content = runner.read_fixture(path, None, follow_symlinks=True)
                        except FileNotFoundError:
                            event = "missing"
                        except (OSError, ValueError) as exc:
                            event = "unusable"
                            record["error"] = str(exc)
                        else:
                            entries.append(dict(path=str(path), sha256=hashlib.sha256(content).hexdigest()))
                            event = "collected"
                    record["event"] = event
                    counts[event] += 1
                    log.write(json.dumps(record) + "\n")
            else:
                counts = dict(created=0, skipped_exists=0, failed=0, unavailable=0)
                digest = hashlib.sha256(MOCK_DATA).hexdigest()
                for raw, path in targets:
                    record = dict(phase="pre-exercise-seeding", batch=batch,
                                  path=str(path) if path is not None else raw,
                                  timestamp=datetime.now(timezone.utc).isoformat())
                    if path is None:
                        event = "unavailable"
                    else:
                        try:
                            file_recorder = None
                            if record_created is not None:
                                file_recorder = lambda created_path, device, inode: record_created(
                                    created_path, digest, device, inode)
                            event = seed_file(
                                path,
                                record_created_directory=record_created_directory,
                                record_created_file=file_recorder,
                            )
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
                manifest = dict(exercise="SPITE-001", source=source, files=entries)
                if source == "synthetic":
                    manifest["mock_files_only"] = True
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
    parser.add_argument("--plan", required=True, help="JSON file containing named groups of paths")
    parser.add_argument("--workspace", required=True, help="Existing exercise workspace")
    parser.add_argument("--output", required=True, help="New directory for manifests and setup results")
    parser.add_argument("--harvest", choices=("synthetic", "real"), default="synthetic",
                        help="Create synthetic credential files or select existing real files")
    args = parser.parse_args()
    summary, failed = prepare(json.loads(Path(args.plan).read_text()), args.workspace, args.output, args.harvest)
    print(json.dumps(summary, indent=2))
    raise SystemExit(1 if failed else 0)
