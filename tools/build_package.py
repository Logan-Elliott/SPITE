#!/usr/bin/env python3
"""Build a self-contained operator ZIP; excludes credentials and lab evidence."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
SLUG="agent-skill-redteam-harness"

if __name__=="__main__":
    version=(ROOT/"VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+",version):
        raise ValueError("VERSION must use semantic version format X.Y.Z")
    package_root="{}-{}-macos".format(SLUG,version)
    output=ROOT/"dist"
    output.mkdir(exist_ok=True)
    target=output/(package_root+".zip")
    files=[]
    for folder in ("macos","tools","skills","variants","profiles","plans","tests"):
        files.extend(p for p in (ROOT/folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix!=".pyc")
    files.extend(ROOT/name for name in (
        "README.md","OPERATOR.md","TEST-CASES.md","RESEARCH.md","DETECTIONS.md","VALIDATION.md",
        "CHANGELOG.md","CONTRIBUTING.md","CODE_OF_CONDUCT.md","SECURITY.md","LICENSE","VERSION","asrt"))
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    with zipfile.ZipFile(target,"w",compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            relative=path.relative_to(ROOT)
            info=zipfile.ZipInfo(package_root+"/"+str(relative))
            info.create_system=3
            mode=0o100755 if path.name=="asrt" or path.suffix in (".command",".sh") else 0o100644
            info.external_attr=mode<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,path.read_bytes())
        hash_info=zipfile.ZipInfo(package_root+"/PACKAGE-HASHES.json")
        hash_info.create_system=3
        hash_info.external_attr=0o100644<<16
        hash_info.compress_type=zipfile.ZIP_DEFLATED
        archive.writestr(hash_info,json.dumps(hashes,indent=2)+"\n")
    # Verify the artifact operators will actually distribute, not only the inputs.
    with zipfile.ZipFile(target,"r") as archive:
        bad_member=archive.testzip()
        if bad_member is not None:
            raise RuntimeError("ZIP integrity failure: "+bad_member)
        embedded=json.loads(archive.read(package_root+"/PACKAGE-HASHES.json"))
        expected_names={package_root+"/"+name for name in embedded}
        expected_names.add(package_root+"/PACKAGE-HASHES.json")
        if set(archive.namelist())!=expected_names or len(archive.namelist())!=len(expected_names):
            raise RuntimeError("Unexpected or duplicate package entries")
        if any(info.date_time!=(1980,1,1,0,0,0) for info in archive.infolist()):
            raise RuntimeError("Package contains a nondeterministic member timestamp")
        if embedded!=hashes:
            raise RuntimeError("Embedded hash manifest differs from package inputs")
        for name,expected in embedded.items():
            if hashlib.sha256(archive.read(package_root+"/"+name)).hexdigest()!=expected:
                raise RuntimeError("Packaged file hash mismatch: "+name)
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    checksum=output/(target.name+".sha256")
    checksum.write_text(digest+"  "+target.name+"\n",encoding="utf-8")
    print(target)
    print("Verified ZIP integrity and {} embedded file hashes.".format(len(hashes)))
    print("SHA-256:",digest)
