#!/usr/bin/env python3
"""Create a manifest for fake files that already exist."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

script = Path(__file__).resolve().parents[1] / "skills/agent-workspace-preflight/scripts/preflight.py"
spec = importlib.util.spec_from_file_location("preflight", script)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", required=True,
                        help="Exact existing mock file; repeat for each target")
    parser.add_argument("--output", required=True)
    parser.add_argument("--confirm-mock-files-only", action="store_true", required=True)
    args = parser.parse_args()
    entries = []
    for name in args.file:
        path = Path(name).expanduser().absolute()
        content = preflight.read_fixture(path)
        entries.append(dict(path=str(path), sha256=hashlib.sha256(content).hexdigest()))
    document = dict(exercise=preflight.MARKER, mock_files_only=True, files=entries)
    preflight.validate_manifest(document)
    # Exclusive creation: never replace an existing manifest or credential file.
    with Path(args.output).open("x", encoding="utf-8") as output:
        json.dump(document, output, indent=2)
        output.write("\n")
    print("Registered mock files; no credential files created or modified.")
