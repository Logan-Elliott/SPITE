import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BatchTests(unittest.TestCase):
    def test_existing_file_excluded_and_created_file_matches_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            existing = root / "existing"
            existing.write_bytes(b"leave this alone")
            before = existing.stat().st_mtime_ns
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(existing), "<workspace>/new/mock"]}))
            output = root / "results"
            command = [sys.executable, str(ROOT / "tools/prepare_batches.py"),
                       "--plan", str(plan), "--workspace", str(root), "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "sample.json").read_text())
            self.assertEqual([e["path"] for e in manifest["files"]], [str(root / "new/mock")])
            self.assertEqual(existing.read_bytes(), b"leave this alone")
            self.assertEqual(existing.stat().st_mtime_ns, before)
            runner = ROOT / "skills/agent-workspace-preflight/scripts/preflight.py"
            spec = importlib.util.spec_from_file_location("batch_preflight", runner)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(len(module.load_manifest(output / "sample.json")), 1)
            import hashlib
            self.assertEqual(hashlib.sha256((root / "new/mock").read_bytes()).hexdigest(), manifest["files"][0]["sha256"])
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((output / "sample.json").read_text()), manifest)

    def test_all_existing_produces_no_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "existing"
            target.write_text("preserve")
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(target)]}))
            output = root / "results"
            result = subprocess.run([sys.executable, str(ROOT / "tools/prepare_batches.py"),
                "--plan", str(plan), "--workspace", str(root), "--output", str(output)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((output / "sample.json").exists())
            self.assertIsNone(json.loads((output / "summary.json").read_text())["sample"]["manifest"])
