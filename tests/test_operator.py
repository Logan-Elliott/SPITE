import argparse
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
with patch.object(sys,"path",[str(ROOT/"tools")]+sys.path):
    spec=importlib.util.spec_from_file_location("exercise_operator",ROOT/"tools/exercise_ops.py")
    op=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(op)


def pcap(segments):
    result=struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,0)
    for src,dst,seq,body in segments:
        tcp=struct.pack("!HHIIBBHHH",src,dst,seq,0,0x50,0x18,65535,0,0)+body
        ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(tcp),0,0,64,6,0,b"\x7f\0\0\1",b"\x7f\0\0\1")
        frame=struct.pack("<I",2)+ip+tcp
        result+=struct.pack("<IIII",0,0,len(frame),len(frame))+frame
    return result


class OperatorTests(unittest.TestCase):
    def test_setup_and_cleanup_are_independent_and_preserve_changed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); workspace=root/"workspace"
            existing=root/"existing";existing.write_text("preserve")
            plan=root/"plan.json"
            plan.write_text(json.dumps({"sample":[str(existing),"<workspace>/.env","<workspace>/other"]}))
            args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True)
            with patch.object(op.subprocess,"Popen",side_effect=AssertionError("Setup must not launch a process")), \
                 patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(args),0)
            self.assertEqual(existing.read_text(),"preserve")
            entries=json.loads((workspace/"batches/sample.json").read_text())["files"]
            self.assertEqual(len(entries),2)
            self.assertTrue((workspace/".trae/skills/agent-workspace-preflight/scripts/preflight.py").is_file())
            self.assertFalse(list(workspace.glob("**/diagnostics.b64")))
            changed=workspace/"other";changed.write_text("modified after setup")
            with patch("builtins.input",return_value="n"),contextlib.redirect_stdout(io.StringIO()):
                op.cleanup(argparse.Namespace(workspace=str(workspace),apply=False))
            self.assertTrue((workspace/".env").is_file())
            with contextlib.redirect_stdout(io.StringIO()):
                op.cleanup(argparse.Namespace(workspace=str(workspace),apply=True))
            self.assertFalse((workspace/".env").exists())
            self.assertEqual(changed.read_text(),"modified after setup")
            self.assertEqual(existing.read_text(),"preserve")
            self.assertTrue((workspace/"ownership.json").exists())

    def test_tcp_reassembly_handles_split_out_of_order_and_retransmission(self):
        raw=pcap([(50000,8765,103,b"def"),(50000,8765,100,b"abc"),(50000,8765,100,b"abc")])
        streams,count=op.tcp_streams(raw)
        self.assertEqual(streams[(50000,8765)],b"abcdef")
        self.assertEqual(count,3)
        for segments in [[(50000,8765,100,b"abc"),(50000,8765,104,b"gap")],
                         [(50000,8765,100,b"abc"),(50000,8765,101,b"xx")]]:
            with self.assertRaises(ValueError):op.tcp_streams(pcap(segments))

    def test_cleanup_ignores_workspace_ledger_edits_and_lists_removals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();workspace=root/"workspace"
            protected=root/"protected";protected.write_text("keep")
            plan=root/"plan.json"
            plan.write_text(json.dumps({"sample":["<workspace>/.env"]}))
            args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True)
            with patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(args),0)
            fake_entry=dict(path=str(protected),sha256=op.hashlib.sha256(protected.read_bytes()).hexdigest(),
                            kind="seed",device=protected.stat().st_dev,inode=protected.stat().st_ino)
            reference=json.loads((workspace/"ownership.json").read_text())
            reference["files"]=[fake_entry]
            (workspace/"ownership.json").write_text(json.dumps(reference))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                op.cleanup(argparse.Namespace(workspace=str(workspace),apply=True))
            self.assertEqual(protected.read_text(),"keep")
            self.assertFalse((workspace/".env").exists())
            self.assertIn(str(workspace/".env"),output.getvalue())
            self.assertNotIn(str(protected),output.getvalue())

    def test_failed_setup_keeps_a_working_cleanup_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();workspace=root/"workspace"
            plan=root/"plan.json"
            plan.write_text(json.dumps({"sample":["<workspace>/.env"]}))
            args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True)
            with patch.object(op.os,"geteuid",return_value=501), \
                 patch.object(op.shutil,"copytree",side_effect=OSError("copy failed")), \
                 contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaisesRegex(OSError,"copy failed"):
                op.setup(args)
            self.assertTrue((workspace/".env").exists())
            with contextlib.redirect_stdout(io.StringIO()):
                op.cleanup(argparse.Namespace(workspace=str(workspace),apply=True))
            self.assertFalse((workspace/".env").exists())

    def test_verify_real_runner_artifacts_and_empty_pcap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();run=root/"run";run.mkdir()
            mock=root/"mock";mock.write_bytes(b"SPITE-001 mock")
            manifest=root/"manifest.json"
            manifest.write_text(json.dumps(dict(exercise="SPITE-001",mock_files_only=True,
                files=[dict(path=str(mock),sha256=op.hashlib.sha256(mock.read_bytes()).hexdigest())])))
            runner=op.module_from(op.SKILL/"scripts/preflight.py","operator_test_runner")
            with patch.object(runner.tempfile,"mkdtemp",return_value=str(run)), \
                 patch.object(runner.http.client,"HTTPConnection") as connection,contextlib.redirect_stdout(io.StringIO()):
                connection.return_value.getresponse.return_value.status=204
                connection.return_value.getresponse.return_value.getheader.side_effect = lambda _name: op.hashlib.sha256(
                    connection.return_value.request.call_args.kwargs["body"]).hexdigest()
                self.assertEqual(runner.run(manifest,True),0)
            body=(run/"diagnostics.b64").read_bytes()
            payload=json.loads(base64.b64decode(body))
            receipt=root/"receipt.jsonl";receipt.write_text(json.dumps(dict(event="collector_received",**payload))+"\n")
            headers=b"POST /spite HTTP/1.1\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"
            request=headers+body
            capture=root/"traffic.pcap"
            capture.write_bytes(pcap([(50000,8765,100,request[:80]),(50000,8765,180,request[80:]),(8765,50000,200,b"HTTP/1.0 204 No Content\r\n\r\n")]))
            args=argparse.Namespace(run=str(run),manifest=str(manifest),receipt=str(receipt),pcap=str(capture),output=str(root/"report.json"),evidence_profile="pcap")
            # Prove verification never invokes fixture reads.
            with patch.object(runner,"read_fixture",side_effect=AssertionError("No hotspot reads")),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.verify(args),0)
            capture.write_bytes(pcap([]));args.output=str(root/"empty.json")
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),2)
            self.assertEqual(json.loads((root/"empty.json").read_text())["status"],"INCOMPLETE")
            capture.write_bytes(b"not a pcap");args.output=str(root/"malformed.json")
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),1)
            self.assertEqual(json.loads((root/"malformed.json").read_text())["status"],"FAIL")
            # Application mismatch must not be disguised as an empty-capture issue.
            receipt.write_text(json.dumps(dict(event="collector_received",run_id=payload["run_id"]))+"\n")
            args.output=str(root/"bad-receipt.json")
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),1)


class ThreeCommandSetupTests(unittest.TestCase):
    def test_default_test_uses_discovered_locations_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir()
            chrome = home / ".config/google-chrome/Default"
            chrome.mkdir(parents=True)
            (chrome / "Login Data").write_bytes(b"existing chrome data")
            firefox = home / ".mozilla/firefox/abc.default-release"
            firefox.mkdir(parents=True)
            trae = home / ".config/Trae/User/globalStorage"
            trae.mkdir(parents=True)
            workspace = root / "workspace"
            argv = ["exercise_ops.py", "test", "--workspace", str(workspace), "--yes"]
            with patch.dict(os.environ, {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}), \
                 patch.object(sys, "argv", argv), patch.object(op.os, "geteuid", return_value=501), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.main(), 0)
            manifest = json.loads((workspace / "batches/representative.json").read_text())
            paths = {entry["path"] for entry in manifest["files"]}
            self.assertIn(str(firefox / "logins.json"), paths)
            self.assertIn(str(trae / "state.vscdb"), paths)
            self.assertNotIn(str(chrome / "Login Data"), paths)
            self.assertEqual(len(paths), 6)
            self.assertEqual((chrome / "Login Data").read_bytes(), b"existing chrome data")
            self.assertFalse((workspace / "config/secrets.json").exists())
            with patch.dict(os.environ, {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.cleanup(argparse.Namespace(workspace=str(workspace), apply=True)), 0)
            self.assertFalse((firefox / "logins.json").exists())
            self.assertFalse((trae / "state.vscdb").exists())
            self.assertEqual((chrome / "Login Data").read_bytes(), b"existing chrome data")

    def test_default_test_prints_prompts_and_prepares_workspace_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
            workspace = root / "workspace"
            output = io.StringIO()
            argv = ["exercise_ops.py", "test", "--workspace", str(workspace),
                    "--file-list", str(plan), "--yes"]
            with patch.object(sys, "argv", argv), patch.object(op.os, "geteuid", return_value=501), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(op.main(), 0)
            self.assertEqual(json.loads((workspace / "target-profile.json").read_text())["id"], "trae-project")
            self.assertTrue((workspace / "runs").is_dir())
            self.assertIn("Let the agent pick the skill", output.getvalue())
            self.assertIn("Tell the agent to use the skill", output.getvalue())
            self.assertIn("```text", output.getvalue())
            self.assertIn("Next command: spite watch " + str(workspace), output.getvalue())
            self.assertIn("Step 1 — Let the agent pick the skill", output.getvalue())
            self.assertIn("Step 2 — Tell the agent to use the skill (only if step 1 did not use the skill)", output.getvalue())
            self.assertIn("Wait for Receiver READY before submitting step 3", output.getvalue())
            self.assertLess(output.getvalue().index("Step 1 —"), output.getvalue().index("Step 2 —"))
            self.assertLess(output.getvalue().index("Next command: spite watch "),
                            output.getvalue().index("Step 3 —"))
            self.assertFalse((workspace / "RUNBOOK.md").exists())
            replay = io.StringIO()
            with patch.object(sys, "argv", ["exercise_ops.py", "prompts", str(workspace)]), \
                 contextlib.redirect_stdout(replay):
                self.assertEqual(op.main(), 0)
            prompt_blocks = r"```text\n(.*?)\n```"
            self.assertEqual(re.findall(prompt_blocks, replay.getvalue(), re.S),
                             re.findall(prompt_blocks, output.getvalue(), re.S))
            self.assertEqual(len(re.findall(prompt_blocks, replay.getvalue(), re.S)), 3)
            self.assertIn("Next command: spite watch " + str(workspace), replay.getvalue())
            self.assertLess(replay.getvalue().index("Next command: spite watch "),
                            replay.getvalue().index("Step 3 —"))
            runner = op.module_from(op.SKILL / "scripts/preflight.py", "workspace_runner")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(workspace / "batches/sample.json"), 0)
            self.assertEqual(len(list((workspace / "runs").glob("spite-*/diagnostics.b64"))), 1)

    def test_named_tests_print_one_prompt_and_expected_result(self):
        for name in ("hierarchy", "benign"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                workspace = root / "workspace"
                argv = ["exercise_ops.py", "test", name, "--workspace", str(workspace), "--yes"]
                if name == "benign":
                    plan = root / "plan.json"
                    plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
                    argv.extend(["--file-list", str(plan)])
                output = io.StringIO()
                with patch.object(sys, "argv", argv), patch.object(op.os, "geteuid", return_value=501), \
                     contextlib.redirect_stdout(output):
                    self.assertEqual(op.main(), 0)
                self.assertEqual(output.getvalue().count("```text"), 1)
                self.assertIn("Next command: spite done " + str(workspace), output.getvalue())
                if name == "hierarchy":
                    self.assertIn("exactly READY with nothing appended", output.getvalue())
                    self.assertFalse((workspace / "batches").exists())
                else:
                    self.assertIn("no command or fake-file access", output.getvalue())
                    self.assertTrue((workspace / "batches/sample.json").is_file())
                self.assertFalse((workspace / "RUNBOOK.md").exists())
                replay = io.StringIO()
                with patch.object(sys, "argv", ["exercise_ops.py", "prompts", str(workspace)]), \
                     contextlib.redirect_stdout(replay):
                    self.assertEqual(op.main(), 0)
                prompt_blocks = r"```text\n(.*?)\n```"
                self.assertEqual(re.findall(prompt_blocks, replay.getvalue(), re.S),
                                 re.findall(prompt_blocks, output.getvalue(), re.S))
                self.assertEqual(len(re.findall(prompt_blocks, replay.getvalue(), re.S)), 1)
                self.assertIn("Expected:", replay.getvalue())
                self.assertIn("Next command: spite done " + str(workspace), replay.getvalue())

    def test_legacy_init_prints_prompts_without_a_runbook(self):
        cases = (
            (None, "main", "Step 1 — Let the agent pick the skill", "watch"),
            ("normal", "main", "Step 1 — Let the agent pick the skill", "watch"),
            ("response", "answer-contamination", "Expected: exactly READY", "done"),
            ("benign", "benign-control", "Expected: a short readiness explanation", "done"),
        )
        for name, variant, marker, next_command in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                plan = root / "plan.json"
                plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
                workspace = root / "workspace"
                output = io.StringIO()
                argv = ["exercise_ops.py", "init", "--workspace", str(workspace), "--yes"]
                if name:
                    argv.extend(["--test", name])
                if name != "response":
                    argv.extend(["--file-list", str(plan)])
                with patch.object(sys, "argv", argv), patch.object(op.os, "geteuid", return_value=501), \
                     contextlib.redirect_stdout(output):
                    self.assertEqual(op.main(), 0)
                self.assertEqual(json.loads((workspace / "setup-result.json").read_text())["skill_variant"], variant)
                self.assertIn(marker, output.getvalue())
                self.assertIn("```text", output.getvalue())
                self.assertIn("Next command: spite " + next_command + " " + str(workspace), output.getvalue())
                self.assertFalse((workspace / "RUNBOOK.md").exists())

    def test_prompts_replay_saved_text_after_workspace_metadata_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan = root / "plan.json"
            plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
            workspace = root / "workspace"
            setup_output = io.StringIO()
            argv = ["exercise_ops.py", "test", "--workspace", str(workspace),
                    "--file-list", str(plan), "--yes"]
            with patch.object(sys, "argv", argv), patch.object(op.os, "geteuid", return_value=501), \
                 contextlib.redirect_stdout(setup_output):
                self.assertEqual(op.main(), 0)
            original = setup_output.getvalue()
            saved_text = original[original.index("\nOpen this workspace in the target agent."):]
            self.assertEqual(saved_text.count("```text"), 3)

            result_path = workspace / "setup-result.json"
            result = json.loads(result_path.read_text())
            result.update(skill_variant="answer-contamination", batches={}, destination="https://changed.example.test")
            result_path.write_text(json.dumps(result))
            target_path = workspace / "target-profile.json"
            target = json.loads(target_path.read_text())
            target.update(display_name="Changed Agent", skill_name="changed-skill")
            target_path.write_text(json.dumps(target))
            preparation_path = workspace / "preparation.json"
            preparation = json.loads(preparation_path.read_text())
            preparation["interpreter"] = "/changed/python"
            preparation_path.write_text(json.dumps(preparation))

            replay = io.StringIO()
            with patch.object(sys, "argv", ["exercise_ops.py", "prompts", str(workspace)]), \
                 contextlib.redirect_stdout(replay):
                self.assertEqual(op.main(), 0)
            self.assertEqual(replay.getvalue(), saved_text)

            state_id = json.loads((workspace / "ownership.json").read_text())["state_id"]
            state_path = root / ".spite-state" / (state_id + ".json")
            state = json.loads(state_path.read_text())
            del state["operator_prompts"]
            state_path.write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, "No saved prompts for this workspace"):
                op.show_prompts(argparse.Namespace(workspace=str(workspace)))

    def test_verify_rejects_literal_run_folder_placeholders(self):
        for name in ("RUN_FOLDER", "OFFLINE_RUN_FOLDER"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "actual run folder"):
                op.verify(argparse.Namespace(run=name))


class ThreeCommandResultsTests(unittest.TestCase):
    def prepared_run(self, root):
        workspace = root / "workspace"
        plan = root / "plan.json"
        plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
        args = argparse.Namespace(plan=str(plan), workspace=str(workspace), yes=True)
        with patch.object(op.os, "geteuid", return_value=501), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.setup(args), 0)
        runner = op.module_from(op.SKILL / "scripts/preflight.py", "watch_test_runner")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run(workspace / "batches/sample.json"), 0)
        first = next((workspace / "runs").iterdir())
        os.utime(first, (1, 1))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run(workspace / "batches/sample.json"), 0)
        second = max((workspace / "runs").iterdir(), key=lambda path: path.stat().st_mtime_ns)
        return workspace, first, second

    def test_watch_offline_finds_newest_run_and_shows_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, first, second = self.prepared_run(Path(temporary).resolve())
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "watch_test")
            output = io.StringIO()
            request = argparse.Namespace(workspace=str(workspace), offline=True, timeout=1)
            with contextlib.redirect_stdout(output):
                self.assertEqual(watch.watch(request, SimpleNamespace(**vars(op))), 0)
            self.assertNotEqual(first, second)
            self.assertIn("Run folder: " + str(second), output.getvalue())
            self.assertIn("SPITE verification: VERIFIED", output.getvalue())
            self.assertNotIn("TC-01", output.getvalue())
            self.assertNotIn("Sensor outcome", output.getvalue())
            self.assertNotIn("EDR/SIEM", output.getvalue())
            self.assertIn("Next: spite done " + str(workspace), output.getvalue())
            reports = [json.loads(path.read_text()) for path in (workspace / "evidence").glob("*watch*.json")]
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0]["status"], "VERIFIED")
            self.assertEqual(reports[0]["run_id"], json.loads((second / "events.jsonl").read_text().splitlines()[0])["run_id"])
            self.assertFalse((workspace / "watch-results.jsonl").exists())

    def test_watch_requests_capture_shutdown_without_killing_launcher(self):
        watch = op.module_from(op.ROOT / "tools/watch_flow.py", "capture_stop_test")
        with tempfile.TemporaryDirectory() as temporary:
            stop_file = Path(temporary) / "capture.stop"

            class Capture:
                stdout = None

                def __init__(self):
                    self.terminated = False
                    self.killed = False

                def poll(self):
                    return None

                def communicate(self, timeout=None):
                    self.timeout = timeout
                    self.stop_contents = stop_file.read_text()
                    return ("", "")

                def terminate(self):
                    self.terminated = True

                def kill(self):
                    self.killed = True

            capture = Capture()
            watch._stop_capture(capture, stop_file)
            self.assertEqual(capture.timeout, 20)
            self.assertEqual(capture.stop_contents, "stop\n")
            self.assertFalse(capture.terminated)
            self.assertFalse(capture.killed)
            self.assertFalse(stop_file.exists())

    def test_watch_capture_shutdown_has_no_unbounded_wait(self):
        watch = op.module_from(op.ROOT / "tools/watch_flow.py", "capture_stop_timeout_test")
        with tempfile.TemporaryDirectory() as temporary:
            stop_file = Path(temporary) / "capture.stop"

            class Output:
                def __init__(self):
                    self.closed = False

                def close(self):
                    self.closed = True

            class Capture:
                def __init__(self):
                    self.stdout = Output()
                    self.timeouts = []
                    self.terminated = False
                    self.killed = False

                def poll(self):
                    return None

                def communicate(self, timeout=None):
                    self.timeouts.append(timeout)
                    raise subprocess.TimeoutExpired("capture", timeout)

                def terminate(self):
                    self.terminated = True

                def kill(self):
                    self.killed = True

            capture = Capture()
            with self.assertRaisesRegex(RuntimeError, "did not stop"):
                watch._stop_capture(capture, stop_file)
            self.assertEqual(capture.timeouts, [20, 5, 5])
            self.assertTrue(capture.terminated)
            self.assertTrue(capture.killed)
            self.assertTrue(capture.stdout.closed)
            self.assertFalse(stop_file.exists())

    def test_capture_stops_tcpdump_when_stop_file_appears(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "traffic.pcap"
            stop_file = root / "capture.stop"
            stop_file.write_text("stop\n")

            class Tcpdump:
                def __init__(self):
                    self.stderr = io.StringIO(
                        "tcpdump: listening on lo0, link-type NULL (BSD loopback)\n")
                    self.stopped = False

                def poll(self):
                    return 0 if self.stopped else None

                def send_signal(self, sent_signal):
                    self.sent_signal = sent_signal
                    self.stopped = True

                def communicate(self, timeout=None):
                    return (None, "1 packet captured\n")

                def kill(self):
                    self.stopped = True

                def wait(self, timeout=None):
                    self.stopped = True
                    return 0

            tcpdump = Tcpdump()
            args = argparse.Namespace(output=str(output), timeout=30,
                                      stop_file=str(stop_file))
            with patch.object(op.sys, "platform", "darwin"), \
                 patch.object(op.os, "geteuid", return_value=0), \
                 patch.object(op.subprocess, "Popen", return_value=tcpdump), \
                 patch.object(op.time, "sleep"), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.capture(args), 0)
            self.assertEqual(tcpdump.sent_signal, op.signal.SIGINT)
            self.assertTrue(output.is_file())

    def test_watch_offline_uses_newest_no_receiver_run_even_if_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, first, second = self.prepared_run(Path(temporary).resolve())
            events_path = second / "events.jsonl"
            events = [json.loads(line) for line in events_path.read_text().splitlines()]
            events[-1]["event"] = "execution_incomplete"
            events[-1].pop("mode")
            events_path.write_text("\n".join(json.dumps(event) for event in events) + "\n")
            (second / "diagnostics.b64").unlink()
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "incomplete_offline_watch_test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                                            SimpleNamespace(**vars(op))), 1)
            self.assertIn("Run folder: " + str(second), output.getvalue())
            self.assertNotIn("Run folder: " + str(first), output.getvalue())
            self.assertIn("SPITE verification: FAIL", output.getvalue())

    def test_watch_offline_skips_newer_receiver_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, first, second = self.prepared_run(Path(temporary).resolve())
            events_path = second / "events.jsonl"
            events = [json.loads(line) for line in events_path.read_text().splitlines()]
            events.insert(-1, dict(events[-1], event="transfer_attempt",
                                   destination="http://127.0.0.1:8765/spite"))
            events[-1]["mode"] = "loopback"
            events_path.write_text("\n".join(json.dumps(event) for event in events) + "\n")
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "receiver_offline_watch_test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                                            SimpleNamespace(**vars(op))), 0)
            self.assertIn("Run folder: " + str(first), output.getvalue())
            self.assertNotIn("Run folder: " + str(second), output.getvalue())

    def test_watch_reports_non_object_events_without_crashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _, second = self.prepared_run(Path(temporary).resolve())
            events_path = second / "events.jsonl"
            events_path.write_text('null\n[]\n"record"\n3\n' + events_path.read_text())
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "malformed_event_watch_test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                                            SimpleNamespace(**vars(op))), 1)
            self.assertIn("Run folder: " + str(second), output.getvalue())
            self.assertIn("SPITE verification: FAIL", output.getvalue())
            reports = [json.loads(path.read_text()) for path in (workspace / "evidence").glob("*watch*.json")]
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0]["status"], "FAIL")

    def test_watch_offline_does_not_verify_older_run_when_newest_events_are_unreadable(self):
        for contents in ('null\n[]\n"record"\n3\n', '{"event":\n', '', None,
                         '{"event":"execution_started","run_id":"newer"}\n'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                workspace, first, second = self.prepared_run(Path(temporary).resolve())
                events_path = second / "events.jsonl"
                if contents is None:
                    events_path.unlink()
                else:
                    events_path.write_text(contents)
                watch = op.module_from(op.ROOT / "tools/watch_flow.py", "unreadable_event_watch_test")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                                                SimpleNamespace(**vars(op))), 1)
                self.assertIn("Run folder: " + str(second), output.getvalue())
                self.assertNotIn("Run folder: " + str(first), output.getvalue())
                self.assertIn("SPITE verification: FAIL", output.getvalue())

    def test_normal_watch_checks_prior_offline_run_and_transfer(self):
        for scenario in (None, "verified", "changed", "incomplete"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                if scenario is None:
                    workspace = root / "workspace"
                    plan = root / "plan.json"
                    plan.write_text(json.dumps({"sample": ["<workspace>/fake.env"]}))
                    with patch.object(op.os, "geteuid", return_value=501), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(op.setup(argparse.Namespace(plan=str(plan), workspace=str(workspace), yes=True)), 0)
                    offline_run = None
                else:
                    workspace, _, offline_run = self.prepared_run(root)
                if scenario == "changed":
                    (offline_run / "diagnostics.b64").write_bytes(b"changed")
                elif scenario == "incomplete":
                    events_path = offline_run / "events.jsonl"
                    events = [json.loads(line) for line in events_path.read_text().splitlines()]
                    events[-1]["event"] = "execution_incomplete"
                    events[-1].pop("mode")
                    events_path.write_text("\n".join(json.dumps(event) for event in events) + "\n")
                    (offline_run / "diagnostics.b64").unlink()
                watch = op.module_from(op.ROOT / "tools/watch_flow.py", "normal_watch_test")
                runner = op.module_from(op.SKILL / "scripts/preflight.py", "normal_watch_runner")
                manifest = workspace / "batches/sample.json"

                class Receiver:
                    stdout = None

                    def __init__(self, receipt):
                        self.receipt = Path(receipt)
                        self.completed = False

                    def wait(self, timeout=None):
                        previous = set((workspace / "runs").iterdir())
                        with patch.object(runner.http.client, "HTTPConnection") as connection, \
                             contextlib.redirect_stdout(io.StringIO()):
                            connection.return_value.getresponse.return_value.status = 204
                            connection.return_value.getresponse.return_value.getheader.side_effect = (
                                lambda _name: op.hashlib.sha256(
                                    connection.return_value.request.call_args.kwargs["body"]).hexdigest())
                            self.assert_run(runner, manifest)
                        transfer_run = next(iter(set((workspace / "runs").iterdir()) - previous))
                        payload = json.loads(base64.b64decode((transfer_run / "diagnostics.b64").read_bytes()))
                        self.receipt.write_text(json.dumps(dict(event="collector_received", **payload)) + "\n")
                        self.completed = True
                        return 0

                    def assert_run(self, runner, manifest):
                        if runner.run(manifest, True) != 0:
                            raise AssertionError("Transfer run failed")

                    def poll(self):
                        return 0 if self.completed else None

                    def terminate(self):
                        self.completed = True

                def start(command, label, timeout):
                    self.assertEqual(label, "Receiver")
                    return Receiver(command[command.index("--output") + 1])

                output = io.StringIO()
                with patch.object(watch, "_start", side_effect=start), contextlib.redirect_stdout(output):
                    status = watch.watch(argparse.Namespace(workspace=str(workspace), offline=False, timeout=1),
                                         SimpleNamespace(**vars(op)))
                self.assertEqual(status, 1 if scenario in ("changed", "incomplete") else 0)
                reports = [json.loads(path.read_text()) for path in (workspace / "evidence").glob("*watch*.json")]
                self.assertEqual(len(reports), 1 if scenario is None else 2)
                if offline_run is not None:
                    self.assertIn(str(offline_run), output.getvalue())
                displayed = [line.removeprefix("SPITE verification: ") for line in output.getvalue().splitlines()
                             if line.startswith("SPITE verification: ")]
                self.assertEqual(displayed, (["FAIL" if scenario in ("changed", "incomplete")
                                              else "VERIFIED"] if offline_run is not None else []) + ["VERIFIED"])
                self.assertNotIn("TC-01", output.getvalue())
                self.assertNotIn("Sensor outcome", output.getvalue())
                self.assertNotIn("EDR/SIEM", output.getvalue())
                self.assertTrue(any(report["status"] == "VERIFIED" for report in reports))
                self.assertFalse((workspace / "watch-results.jsonl").exists())
                self.assertIn("Next: spite done " + str(workspace), output.getvalue())

    def test_watch_translates_failed_checks_without_internal_keys(self):
        watch = op.module_from(op.ROOT / "tools/watch_flow.py", "watch_verification_test")
        report = {"status": "FAIL", "checks": {"all_file_hashes_match": False}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            watch._print_verification(report)
        self.assertIn("SPITE verification: FAIL", output.getvalue())
        self.assertIn("At least one staged file hash differed", output.getvalue())
        self.assertNotIn("all_file_hashes_match", output.getvalue())
        self.assertNotIn("TC-03", output.getvalue())
        self.assertNotIn("Sensor outcome", output.getvalue())
        self.assertNotIn("EDR/SIEM", output.getvalue())

    def test_watch_rejects_saved_paths_outside_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace, _, _ = self.prepared_run(root)
            saved_path = workspace / "verification.json"
            saved = json.loads(saved_path.read_text())
            saved["output"] = str(root / "outside.json")
            saved_path.write_text(json.dumps(saved))
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "watch_path_test")
            with self.assertRaisesRegex(ValueError, "inside the workspace"):
                watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                            SimpleNamespace(**vars(op)))

    def test_watch_returns_fail_for_changed_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _, newest = self.prepared_run(Path(temporary).resolve())
            (newest / "diagnostics.b64").write_bytes(b"changed")
            watch = op.module_from(op.ROOT / "tools/watch_flow.py", "failed_watch_test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(watch.watch(argparse.Namespace(workspace=str(workspace), offline=True),
                                            SimpleNamespace(**vars(op))), 1)
            reports = [json.loads(path.read_text()) for path in (workspace / "evidence").glob("*watch*.json")]
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0]["status"], "FAIL")
            self.assertIn("SPITE verification: FAIL", output.getvalue())
            self.assertFalse((workspace / "watch-results.jsonl").exists())

    def test_done_cleans_without_report_or_watch_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _, second = self.prepared_run(Path(temporary).resolve())
            self.assertFalse((workspace / "ENGAGEMENT-REPORT.json").exists())
            self.assertFalse((workspace / "watch-results.jsonl").exists())
            output = io.StringIO()
            argv = ["exercise_ops.py", "done", str(workspace), "--yes"]
            with patch.object(sys, "argv", argv), patch("builtins.input", side_effect=AssertionError("No prompt expected")), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(op.main(), 0)
            self.assertFalse((workspace / "fake.env").exists())
            self.assertTrue(second.is_dir())
            self.assertIn(str(workspace / "fake.env"), output.getvalue())
            self.assertIn("Removed ", output.getvalue())
            self.assertFalse((workspace / "ENGAGEMENT-REPORT.json").exists())

    def test_done_asks_only_for_cleanup_and_preserves_changed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            plan = root / "plan.json"
            existing = root / "existing.env"
            existing.write_text("real contents")
            plan.write_text(json.dumps({"sample": ["<workspace>/fake.env", str(existing)]}))
            with patch.object(op.os, "geteuid", return_value=501), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(argparse.Namespace(plan=str(plan), workspace=str(workspace), yes=True)), 0)
            changed = workspace / "fake.env"
            changed.write_text("operator changed this file")
            old_report = workspace / "ENGAGEMENT-REPORT.json"
            old_report.write_text("not valid JSON")
            output = io.StringIO()
            argv = ["exercise_ops.py", "done", str(workspace)]
            with patch.object(sys, "argv", argv), patch("builtins.input", return_value="y") as answer, \
                 contextlib.redirect_stdout(output):
                self.assertEqual(op.main(), 0)
            answer.assert_called_once()
            self.assertIn("Remove the ", answer.call_args.args[0])
            self.assertEqual(changed.read_text(), "operator changed this file")
            self.assertEqual(existing.read_text(), "real contents")
            self.assertIn("Preserve " + str(changed), output.getvalue())
            self.assertEqual(old_report.read_text(), "not valid JSON")


if __name__=="__main__":unittest.main()
