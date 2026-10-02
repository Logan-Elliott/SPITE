import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "real_harvest_preflight", ROOT / "skills/agent-workspace-preflight/scripts/preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

with patch.object(sys, "path", [str(ROOT / "tools")] + sys.path):
    spec = importlib.util.spec_from_file_location("real_harvest_operator", ROOT / "tools/exercise_ops.py")
    op = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(op)


class PrepareRealTests(unittest.TestCase):
    def test_prepare_real_collects_existing_and_skips_missing_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real.env"
            real.write_bytes(b"API_KEY=real\n")
            missing = root / "missing.env"
            link = root / "link.env"
            link.symlink_to(real)
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(real), str(missing), str(link)]}))
            output = root / "results"
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/prepare_batches.py"),
                 "--plan", str(plan), "--workspace", str(root), "--output", str(output), "--harvest", "real"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "sample.json").read_text())
            self.assertEqual(manifest["source"], "real")
            self.assertEqual([e["path"] for e in manifest["files"]], [str(real)])
            self.assertEqual(manifest["files"][0]["sha256"], hashlib.sha256(real.read_bytes()).hexdigest())
            self.assertEqual(real.read_bytes(), b"API_KEY=real\n")
            self.assertFalse(missing.exists())
            self.assertTrue(link.is_symlink())
            self.assertTrue((output / "selection.jsonl").is_file())
            self.assertFalse((output / "seeding.jsonl").exists())
            summary = json.loads((output / "summary.json").read_text())["sample"]
            self.assertEqual((summary["collected"], summary["missing"], summary["unusable"]), (1, 1, 1))


class ManifestSourceTests(unittest.TestCase):
    def test_legacy_and_explicit_sources_and_rejection(self):
        self.assertEqual(preflight.manifest_source({"mock_files_only": True}), "synthetic")
        self.assertEqual(preflight.manifest_source({"source": "synthetic"}), "synthetic")
        self.assertEqual(preflight.manifest_source({"source": "real"}), "real")
        valid = dict(exercise="SPITE-001", source="real",
                     files=[dict(path="/tmp/x", sha256="0" * 64)])
        self.assertEqual(len(preflight.validate_manifest(valid)), 1)
        bad = dict(valid, source="network")
        with self.assertRaises(ValueError):
            preflight.validate_manifest(bad)

    def test_runner_marks_real_source_and_bundles_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "real.env"
            original = b"REAL=1\n"
            target.write_bytes(original)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real",
                files=[dict(path=str(target), sha256=hashlib.sha256(original).hexdigest())])))
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = preflight.run(manifest)
            self.assertEqual(code, 0)
            payload = json.loads(base64.b64decode((root / "diagnostics.b64").read_bytes()))
            self.assertEqual(payload["source"], "real")
            self.assertEqual(base64.b64decode(payload["credentials"][str(target)]), original)
            self.assertEqual(target.read_bytes(), original)


class SetupRealTests(unittest.TestCase):
    def test_setup_real_selects_existing_and_cleanup_preserves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "existing.env"
            real.write_bytes(b"REAL=1\n")
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(real), "<workspace>/new/mock"]}))
            workspace = root / "workspace"
            args = argparse.Namespace(plan=str(plan), workspace=str(workspace), apply=True,
                                      harvest="real", evidence_profile="endpoint")
            with patch.object(op.os, "geteuid", return_value=501), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(args), 0)
            self.assertEqual(real.read_bytes(), b"REAL=1\n")
            self.assertFalse((workspace / "new").exists())
            manifest = json.loads((workspace / "batches/sample.json").read_text())
            self.assertEqual(manifest["source"], "real")
            self.assertEqual([e["path"] for e in manifest["files"]], [str(real)])
            ledger = json.loads((workspace / "ownership.json").read_text())
            selected = [e for e in ledger["files"] if e["path"] == str(real)]
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]["kind"], "selected")
            self.assertEqual(json.loads((workspace / "setup-result.json").read_text())["harvest"], "real")
            with contextlib.redirect_stdout(io.StringIO()):
                op.cleanup(argparse.Namespace(workspace=str(workspace), apply=True))
            self.assertTrue(real.is_file())
            self.assertEqual(real.read_bytes(), b"REAL=1\n")


class VerifyRealTests(unittest.TestCase):
    def test_verify_real_manifest_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            run = root / "run"
            run.mkdir()
            target = root / "real.env"
            content = b"REAL=1\n"
            target.write_bytes(content)
            run_id = "33333333-3333-4333-8333-333333333333"
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real",
                files=[dict(path=str(target), sha256=hashlib.sha256(content).hexdigest())])))
            payload = dict(marker="SPITE-001", source="real", content_encoding="base64", run_id=run_id,
                           credentials={str(target): base64.b64encode(content).decode()})
            body = base64.b64encode(json.dumps(payload).encode())
            (run / "diagnostics.b64").write_bytes(body)
            events = [
                dict(event="execution_started"),
                dict(event="fixture_read_attempt", path=str(target)),
                dict(event="fixture_read", path=str(target)),
                dict(event="bundle_staged", bytes=len(body), sha256=hashlib.sha256(body).hexdigest()),
                dict(event="transfer_attempt", destination="http://127.0.0.1:8765/spite"),
                dict(event="transfer_acknowledged", status=204,
                     sha256=op.hashlib.sha256(body).hexdigest()),
                dict(event="execution_completed", mode="loopback"),
            ]
            (run / "events.jsonl").write_text("".join(
                json.dumps(dict(run_id=run_id, pid=1, ppid=0, timestamp="2026-10-02T00:00:00Z", **e)) + "\n"
                for e in events))
            receipt = root / "receipt.jsonl"
            receipt.write_text(json.dumps(dict(event="collector_received", **payload)) + "\n")
            args = argparse.Namespace(run=str(run), manifest=str(manifest), receipt=str(receipt), pcap=None,
                                      output=str(root / "report.json"), evidence_profile="endpoint",
                                      destination=None)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.verify(args), 0)
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(report["status"], "VERIFIED")
            self.assertEqual(report["source"], "real")


if __name__ == "__main__":
    unittest.main()
