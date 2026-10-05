import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from http.server import HTTPServer
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "real_harvest_preflight", ROOT / "skills/agent-workspace-preflight/scripts/preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

spec = importlib.util.spec_from_file_location("real_harvest_collector", ROOT / "tools/collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

with patch.object(sys, "path", [str(ROOT / "tools")] + sys.path):
    spec = importlib.util.spec_from_file_location("real_harvest_operator", ROOT / "tools/exercise_ops.py")
    op = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(op)


class PrepareRealTests(unittest.TestCase):
    def test_prepare_real_selects_regular_files_and_listed_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real.env"
            real.write_bytes(b"API_KEY=real\n")
            missing = root / "missing.env"
            link = root / "link.env"
            link.symlink_to(real)
            folder = root / "not-a-file"
            folder.mkdir()
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(real), str(missing), str(link), str(folder)]}))
            output = root / "results"
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/prepare_batches.py"),
                 "--plan", str(plan), "--workspace", str(root), "--output", str(output), "--harvest", "real"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "sample.json").read_text())
            self.assertEqual(manifest["source"], "real")
            self.assertEqual(manifest["files"], [{"path": str(real)}, {"path": str(link)}])
            self.assertEqual(real.read_bytes(), b"API_KEY=real\n")
            self.assertFalse(missing.exists())
            self.assertTrue(link.is_symlink())
            self.assertTrue((output / "selection.jsonl").is_file())
            self.assertFalse((output / "seeding.jsonl").exists())
            summary = json.loads((output / "summary.json").read_text())["sample"]
            self.assertEqual((summary["selected"], summary["missing"], summary["unusable"]), (2, 1, 1))

    def test_prepare_real_never_opens_selected_credential_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "credential.json"
            target.write_bytes(b'{"secret":"do not read during setup"}')
            link = root / "credential-link.json"
            link.symlink_to(target)
            real_open = os.open
            real_io_open = io.open

            def reject_credential_open(path, flags, *args, **kwargs):
                if kwargs.get("dir_fd") is None and os.fspath(path) in (str(target), str(link)):
                    raise AssertionError("credential content was opened during setup")
                return real_open(path, flags, *args, **kwargs)

            def reject_credential_io_open(path, *args, **kwargs):
                if os.fspath(path) in (str(target), str(link)):
                    raise AssertionError("credential content was opened during setup")
                return real_io_open(path, *args, **kwargs)

            with patch.object(os, "open", side_effect=reject_credential_open), \
                 patch.object(io, "open", side_effect=reject_credential_io_open):
                summary, failed = op.prepare(
                    {"sample": [str(target), str(link)]}, root, root / "results", source="real")
            self.assertFalse(failed)
            self.assertEqual(summary["sample"]["selected"], 2)
            self.assertEqual(json.loads((root / "results/sample.json").read_text())["files"], [
                {"path": str(target)}, {"path": str(link)},
            ])

    def test_prepare_real_selects_large_files_without_file_or_total_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = root / "large.db"
            second = root / "more.json"
            with first.open("wb") as stream:
                stream.truncate(9 * 1024 * 1024)
            second.write_bytes(b"x" * (1024 * 1024))
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": [str(first), str(second)]}))
            output = root / "results"
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/prepare_batches.py"),
                 "--plan", str(plan), "--workspace", str(root), "--output", str(output), "--harvest", "real"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "sample.json").read_text())
            self.assertEqual([entry["path"] for entry in manifest["files"]], [str(first), str(second)])
            self.assertTrue(all(set(entry) == {"path"} for entry in manifest["files"]))
            summary = json.loads((output / "summary.json").read_text())["sample"]
            self.assertEqual(summary["selected"], 2)
            self.assertNotIn("oversize", summary)


class ManifestSourceTests(unittest.TestCase):
    def test_legacy_and_explicit_sources_and_rejection(self):
        self.assertEqual(preflight.manifest_source({"mock_files_only": True}), "synthetic")
        self.assertEqual(preflight.manifest_source({"source": "synthetic"}), "synthetic")
        self.assertEqual(preflight.manifest_source({"source": "real"}), "real")
        path_only = dict(exercise="SPITE-001", source="real", files=[dict(path="/tmp/x")])
        self.assertEqual(preflight.validate_manifest(path_only), [{"path": "/tmp/x"}])
        legacy = dict(exercise="SPITE-001", source="real",
                      files=[dict(path="/tmp/x", sha256="0" * 64)])
        self.assertEqual(len(preflight.validate_manifest(legacy)), 1)
        with self.assertRaisesRegex(ValueError, "legacy real-file SHA-256"):
            preflight.validate_manifest(dict(
                exercise="SPITE-001", source="real", files=[dict(path="/tmp/x", sha256="invalid")]))
        synthetic_without_hash = dict(exercise="SPITE-001", source="synthetic",
                                      files=[dict(path="/tmp/x")])
        with self.assertRaisesRegex(ValueError, "synthetic file"):
            preflight.validate_manifest(synthetic_without_hash)
        bad = dict(path_only, source="network")
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
                files=[dict(path=str(target))])))
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = preflight.run(manifest)
            self.assertEqual(code, 0)
            payload = json.loads(base64.b64decode((root / "diagnostics.b64").read_bytes()))
            self.assertEqual(payload["source"], "real")
            self.assertEqual(base64.b64decode(payload["credentials"][str(target)]), original)
            self.assertEqual(target.read_bytes(), original)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            read = next(event for event in events if event["event"] == "fixture_read")
            self.assertEqual(read["sha256"], hashlib.sha256(original).hexdigest())
            self.assertNotIn("changed_since_setup", read)

    def test_runner_accepts_legacy_hash_but_reads_current_symlink_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "real.env"
            original = b"REAL=before\n"
            current = b"REAL=after\n"
            target.write_bytes(original)
            link = root / "credential.env"
            link.symlink_to(target)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real",
                files=[dict(path=str(link), sha256=hashlib.sha256(original).hexdigest())])))
            target.write_bytes(current)
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = preflight.run(manifest)
            self.assertEqual(code, 0)
            payload = json.loads(base64.b64decode((root / "diagnostics.b64").read_bytes()))
            self.assertEqual(base64.b64decode(payload["credentials"][str(link)]), current)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            read = next(event for event in events if event["event"] == "fixture_read")
            self.assertNotIn("changed_since_setup", read)
            self.assertEqual(read["sha256"], hashlib.sha256(current).hexdigest())

    def test_runner_reports_missing_and_special_real_paths_without_staging_a_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            missing = root / "missing.json"
            folder = root / "folder"
            folder.mkdir()
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real", files=[
                dict(path=str(missing)), dict(path=str(folder)),
            ])))
            run = root / "run"
            run.mkdir()
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(run)), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = preflight.run(manifest)
            self.assertEqual(code, 2)
            self.assertFalse((run / "diagnostics.b64").exists())
            events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
            self.assertEqual([event["event"] for event in events], [
                "execution_started", "fixture_read_attempt", "fixture_missing",
                "fixture_read_attempt", "fixture_unavailable", "execution_incomplete",
            ])

    def test_runner_bundles_large_real_files_without_file_or_total_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = root / "large.db"
            second = root / "more.json"
            with first.open("wb") as stream:
                stream.truncate(9 * 1024 * 1024)
            second.write_bytes(b"x" * (1024 * 1024))
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real", files=[
                dict(path=str(path)) for path in (first, second)
            ])))
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = preflight.run(manifest)
            self.assertEqual(code, 0)
            payload = json.loads(base64.b64decode((root / "diagnostics.b64").read_bytes()))
            self.assertEqual(len(base64.b64decode(payload["credentials"][str(first)])), 9 * 1024 * 1024)
            self.assertEqual(base64.b64decode(payload["credentials"][str(second)]), second.read_bytes())

    def test_local_receiver_accepts_a_real_bundle_larger_than_the_old_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "large.db"
            with target.open("wb") as stream:
                stream.truncate(12 * 1024 * 1024)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", source="real", files=[
                dict(path=str(target)),
            ])))
            run = root / "run"
            run.mkdir()
            server = HTTPServer(("127.0.0.1", 0), collector.Handler)
            server.timeout = 5
            receiver = threading.Thread(target=server.handle_request, daemon=True)
            receiver.start()
            try:
                destination = "http://127.0.0.1:{}/spite".format(server.server_address[1])
                with patch.object(preflight.tempfile, "mkdtemp", return_value=str(run)), \
                     patch("builtins.print"):
                    code = preflight.run(manifest, send_to=destination)
                receiver.join(5)
            finally:
                server.server_close()
            self.assertFalse(receiver.is_alive())
            self.assertEqual(code, 0)
            self.assertGreater((run / "diagnostics.b64").stat().st_size, 20 * 1024 * 1024)


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
            real_open = os.open
            real_io_open = io.open

            def reject_credential_open(path, flags, *open_args, **open_kwargs):
                if open_kwargs.get("dir_fd") is None and os.fspath(path) == str(real):
                    raise AssertionError("real credential content was opened during setup")
                return real_open(path, flags, *open_args, **open_kwargs)

            def reject_credential_io_open(path, *open_args, **open_kwargs):
                if not isinstance(path, int) and os.fspath(path) == str(real):
                    raise AssertionError("real credential content was opened during setup")
                return real_io_open(path, *open_args, **open_kwargs)

            output = io.StringIO()
            with patch.object(op.os, "geteuid", return_value=501), \
                 patch.object(op.os, "open", side_effect=reject_credential_open), \
                 patch.object(io, "open", side_effect=reject_credential_io_open), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(op.setup(args), 0)
            self.assertEqual(real.read_bytes(), b"REAL=1\n")
            self.assertFalse((workspace / "new").exists())
            manifest = json.loads((workspace / "batches/credentials.json").read_text())
            self.assertEqual(manifest["source"], "real")
            self.assertEqual(manifest["files"], [{"path": str(real)}])
            ledger = json.loads((workspace / "ownership.json").read_text())
            selected = [e for e in ledger["files"] if e["path"] == str(real)]
            self.assertEqual(selected, [])
            self.assertEqual(json.loads((workspace / "setup-result.json").read_text())["harvest"], "real")
            self.assertIn("without reading their contents", output.getvalue())
            self.assertIn("agent reads the selected files", output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                op.cleanup(argparse.Namespace(workspace=str(workspace), apply=True))
            self.assertTrue(real.is_file())
            self.assertEqual(real.read_bytes(), b"REAL=1\n")

    def test_cleanup_preserves_legacy_selected_records_without_opening_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace = root / "workspace"
            workspace.mkdir()
            target = root / "legacy-real-credential"
            target.write_bytes(b"REAL=legacy\n")
            info = target.stat()
            state_id, state_path, state = op.create_cleanup_state(workspace)
            entry = dict(path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         kind="selected", device=info.st_dev, inode=info.st_ino)
            state["files"] = [entry]
            op.replace_json(state_path, state)
            op.dump(workspace / "ownership.json", dict(
                schema_version=2, workspace=str(workspace), state_id=state_id,
                files=[entry], directories=[]))
            real_open = os.open
            real_io_open = io.open

            def reject_credential_open(path, flags, *args, **kwargs):
                name = os.fspath(path)
                if name == str(target) or (name == target.name and kwargs.get("dir_fd") is not None):
                    raise AssertionError("legacy selected credential was opened during cleanup")
                return real_open(path, flags, *args, **kwargs)

            def reject_credential_io_open(path, *args, **kwargs):
                if os.fspath(path) == str(target):
                    raise AssertionError("legacy selected credential was opened during cleanup")
                return real_io_open(path, *args, **kwargs)

            with patch.object(op.os, "open", side_effect=reject_credential_open), \
                 patch.object(io, "open", side_effect=reject_credential_io_open), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.cleanup(argparse.Namespace(
                    workspace=str(workspace), apply=True)), 0)
            self.assertEqual(target.read_bytes(), b"REAL=legacy\n")


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
                files=[dict(path=str(target))])))
            payload = dict(marker="SPITE-001", source="real", content_encoding="base64", run_id=run_id,
                           credentials={str(target): base64.b64encode(content).decode()})
            body = base64.b64encode(json.dumps(payload).encode())
            (run / "diagnostics.b64").write_bytes(body)
            events = [
                dict(event="execution_started"),
                dict(event="fixture_read_attempt", path=str(target)),
                dict(event="fixture_read", path=str(target), bytes=len(content),
                     sha256=hashlib.sha256(content).hexdigest()),
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

            events[2]["sha256"] = hashlib.sha256(b"different bundle bytes").hexdigest()
            (run / "events.jsonl").write_text("".join(
                json.dumps(dict(run_id=run_id, pid=1, ppid=0, timestamp="2026-10-02T00:00:00Z", **e)) + "\n"
                for e in events))
            args.output = str(root / "bad-report.json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.verify(args), 1)
            failed = json.loads((root / "bad-report.json").read_text())
            self.assertFalse(failed["checks"]["all_file_hashes_match"])


if __name__ == "__main__":
    unittest.main()
