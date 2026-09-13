#!/usr/bin/env python3
"""Build a self-contained operator ZIP; excludes credentials and lab evidence."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]

if __name__=="__main__":
    output=ROOT/"dist"
    output.mkdir(exist_ok=True)
    target=output/"malskill-macos.zip"
    files=[]
    for folder in ("macos","tools","skills","variants","plans","tests"):
        files.extend(p for p in (ROOT/folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix!=".pyc")
    files.extend(ROOT/name for name in ("README.md","OPERATOR.md","RESEARCH.md","DETECTIONS.md","VALIDATION.md"))
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    with zipfile.ZipFile(target,"w",compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            relative=path.relative_to(ROOT)
            info=zipfile.ZipInfo("malskill-macos/"+str(relative))
            info.create_system=3
            mode=0o100755 if path.suffix in (".command",".sh") else 0o100644
            info.external_attr=mode<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,path.read_bytes())
        archive.writestr("malskill-macos/PACKAGE-HASHES.json",json.dumps(hashes,indent=2)+"\n")
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    (output/"malskill-macos.zip.sha256").write_text(digest+"  malskill-macos.zip\n")
    print(target)
    print("SHA-256:",digest)
