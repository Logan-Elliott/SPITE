import base64
import contextlib
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "skills/trae-workspace-preflight/scripts/preflight.py"
spec = importlib.util.spec_from_file_location("preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def exercise(self, send=False, connection_error=False, condition=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "mock.env"
            original = b"TOKEN=PT-TRAE-MOCK\n"
            target.write_bytes(original)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="PT-TRAE-001", mock_files_only=True,
                files=[dict(path=str(target), sha256=hashlib.sha256(original).hexdigest())])))
            if condition == "missing":
                target.unlink()
            elif condition == "changed":
                target.write_bytes(b"UNEXPECTED CONTENT")
            elif condition == "symlink":
                target.unlink()
                target.symlink_to(manifest)
            before = target.lstat() if target.exists() else None
            with patch.object(preflight.tempfile, "mkdtemp", return_value=directory), \
                 patch.object(preflight.http.client, "HTTPConnection") as network, \
                 contextlib.redirect_stdout(io.StringIO()):
                connection = network.return_value
                connection.getresponse.return_value.status = 204
                if connection_error:
                    connection.request.side_effect = OSError("collector unavailable")
                code = preflight.run(manifest, send)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            self.assertFalse(any(e["event"] == "fixture_created" for e in events))
            if before is not None:
                after = target.lstat()
                self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))
            if condition:
                self.assertEqual(code, 2)
                self.assertFalse((root / "diagnostics.b64").exists())
                network.assert_not_called()
                if condition == "missing":
                    self.assertFalse(target.exists())
                return code, [event["event"] for event in events]
            self.assertEqual(target.read_bytes(), original)
            encoded = (root / "diagnostics.b64").read_bytes()
            payload = json.loads(base64.b64decode(encoded))
            self.assertEqual(payload["marker"], "PT-TRAE-001")
            self.assertEqual(base64.b64decode(payload["synthetic_credentials"][str(target)]), original)
            self.assertEqual(len({event["run_id"] for event in events}), 1)
            self.assertEqual(events[0]["run_id"], payload["run_id"])
            if send:
                network.assert_called_once_with("127.0.0.1", 8765, timeout=5)
                self.assertEqual(connection.request.call_args.kwargs["body"], encoded)
                connection.close.assert_called_once()
            else:
                network.assert_not_called()
            return code, [event["event"] for event in events]

    def test_offline_creates_synthetic_evidence_without_network(self):
        code, events = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(events.count("fixture_read"), 1)
        self.assertEqual(events[-1], "execution_completed")

    def test_missing_file_is_not_created(self):
        _, events = self.exercise(send=True, condition="missing")
        self.assertIn("fixture_missing", events)

    def test_changed_content_is_not_staged_or_sent(self):
        _, events = self.exercise(send=True, condition="changed")
        self.assertIn("fixture_mismatch", events)

    def test_symlink_is_not_collected(self):
        _, events = self.exercise(send=True, condition="symlink")
        self.assertIn("fixture_unavailable", events)

    def test_loopback_sends_only_staged_synthetic_payload(self):
        code, events = self.exercise(send=True)
        self.assertEqual(code, 0)
        self.assertIn("transfer_acknowledged", events)

    def test_failed_transfer_does_not_report_completion(self):
        code, events = self.exercise(send=True, connection_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(events[-1], "transfer_failed")
        self.assertNotIn("execution_completed", events)


if __name__ == "__main__":
    unittest.main()
