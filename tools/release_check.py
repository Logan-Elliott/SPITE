#!/usr/bin/env python3
"""Run the repository checks used before publishing an operator archive."""
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def run(command):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def validate_sources():
    python_files = sorted(ROOT.rglob("*.py"))
    json_files = sorted(
        path for path in ROOT.rglob("*.json")
        if "dist" not in path.parts and "__pycache__" not in path.parts
    )
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for path in json_files:
        json.loads(path.read_text(encoding="utf-8"))
    print("Validated {} Python and {} JSON files.".format(len(python_files), len(json_files)))


def validate_markdown_links():
    checked = 0
    for document in sorted(ROOT.glob("*.md")):
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            if "://" in target or target.startswith(("#", "mailto:")):
                continue
            relative = target.split("#", 1)[0]
            if not (document.parent / relative).exists():
                raise ValueError("Broken local link in {}: {}".format(document.name, target))
            checked += 1
    print("Validated {} local Markdown links.".format(checked))


def main():
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    validate_sources()
    validate_markdown_links()
    if shutil.which("zsh"):
        launchers = sorted((ROOT / "macos").glob("*.command"))
        run(["zsh", "-n", str(ROOT / "spite"), str(ROOT / "macos/launch.sh"), *map(str, launchers)])
    else:
        print("zsh unavailable; launcher syntax check skipped on this platform.")
    builder=[sys.executable, str(ROOT / "tools/build_package.py")]
    run(builder)
    version=(ROOT/"VERSION").read_text(encoding="utf-8").strip()
    archive=ROOT/"dist"/("spite-{}-macos.zip".format(version))
    first=hashlib.sha256(archive.read_bytes()).hexdigest()
    run(builder)
    second=hashlib.sha256(archive.read_bytes()).hexdigest()
    if first!=second:
        raise RuntimeError("Package build is not reproducible")
    print("Reproducible package SHA-256:",second)
    print("Release checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
