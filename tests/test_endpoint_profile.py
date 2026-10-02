"""Evidence-profile tests use synthetic artifacts; no exercise invocation."""
import argparse
import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_operator import op, pcap


class EndpointProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def artifacts(self, profile="endpoint", destination=None):
        run = self.root / "run"
        run.mkdir()
        target = str(self.root / "pre-seeded-mock")
        content = b"SPITE-001 synthetic artifact test"
        run_id = "22222222-2222-4222-8222-222222222222"
        manifest = dict(exercise="SPITE-001", mock_files_only=True,
                        files=[dict(path=target,sha256=op.hashlib.sha256(content).hexdigest())])
        payload = dict(marker="SPITE-001",content_encoding="base64",run_id=run_id,
                       synthetic_credentials={target:base64.b64encode(content).decode()})
        body = base64.b64encode(json.dumps(payload).encode())
        if destination:
            status = 101 if destination.startswith(("ws://","wss://")) else 204
            transfers = [dict(event="transfer_attempt",destination=destination),
                         dict(event="transfer_acknowledged",status=status,sha256=op.hashlib.sha256(body).hexdigest()),
                         dict(event="execution_completed",mode="remote")]
        else:
            transfers = [dict(event="transfer_attempt",destination="http://127.0.0.1:8765/spite"),
                         dict(event="transfer_acknowledged",status=204,sha256=op.hashlib.sha256(body).hexdigest()),
                         dict(event="execution_completed",mode="loopback")]
        event_data = [
            dict(event="execution_started"),
            dict(event="fixture_read_attempt",path=target),
            dict(event="fixture_read",path=target),
            dict(event="bundle_staged",bytes=len(body),sha256=op.hashlib.sha256(body).hexdigest()),
            *transfers,
        ]
        events = [dict(run_id=run_id,pid=123,ppid=100,timestamp="2026-09-13T00:00:00Z",**e) for e in event_data]
        (run / "events.jsonl").write_text("".join(json.dumps(e)+"\n" for e in events))
        (run / "diagnostics.b64").write_bytes(body)
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        receipt = self.root / "receipt.jsonl"
        receipt.write_text(json.dumps(dict(event="collector_received",**payload))+"\n")
        args = argparse.Namespace(run=str(run),manifest=str(manifest_path),
                                  receipt=None if destination else str(receipt),
                                  pcap=None,output=str(self.root / "report.json"),
                                  evidence_profile=profile,destination=destination)
        return args, body

    def verify_endpoint(self, args):
        with patch("builtins.input",side_effect=AssertionError("Unexpected prompt")), \
             patch.object(op,"tcp_streams",side_effect=AssertionError("Endpoint must not parse PCAP")), \
             patch.object(op.subprocess,"Popen",side_effect=AssertionError("No sudo/tcpdump/processes")), \
             contextlib.redirect_stdout(io.StringIO()):
            status = op.verify(args)
        return status, json.loads(Path(args.output).read_text())

    def test_endpoint_pass_without_pcap_is_explicitly_scoped(self):
        args, _ = self.artifacts()
        status, report = self.verify_endpoint(args)
        self.assertEqual(status,0)
        self.assertEqual(report["status"],"VERIFIED")
        self.assertEqual(report["evidence_profile"],"endpoint")
        self.assertEqual(report["status_scope"],"endpoint checks only")
        self.assertFalse(report["pcap_collected"])
        self.assertFalse(report["pcap_verified"])
        self.assertFalse(report["external_telemetry_mechanically_verified"])
        self.assertEqual(report["external_validation_required"],op.EXTERNAL_VALIDATION)
        self.assertNotIn("pcap_sha256",report)
        self.assertFalse(any(key.startswith("pcap_") for key in report["checks"]))
        self.assertFalse((self.root / "pre-seeded-mock").exists())

    def test_endpoint_missing_application_evidence_fails(self):
        args, _ = self.artifacts()
        for number, name in enumerate(["receipt.jsonl","manifest.json","run/events.jsonl","run/diagnostics.b64"]):
            with self.subTest(name=name):
                path=self.root/name
                data=path.read_bytes()
                path.unlink()
                args.output=str(self.root / ("missing-{}.json".format(number)))
                status,report=self.verify_endpoint(args)
                self.assertEqual(status,1)
                self.assertEqual(report["status"],"FAIL")
                path.write_bytes(data)

    def test_endpoint_inconsistent_receipt_or_events_fail(self):
        args, _ = self.artifacts()
        receipt=Path(args.receipt)
        original=receipt.read_text()
        receipt.write_text(original.replace("22222222-2222-4222-8222-222222222222","wrong-run"))
        status, report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["receipt_matches_bundle"])
        receipt.write_text(original)
        log=Path(args.run)/"events.jsonl"
        events=[json.loads(line) for line in log.read_text().splitlines()]
        events[-2]["status"]=500
        log.write_text("".join(json.dumps(e)+"\n" for e in events))
        args.output=str(self.root/"bad-ack.json")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["completed_loopback"])

    def test_endpoint_rejects_changed_hash_paths_and_invalid_manifest(self):
        args, _ = self.artifacts()
        manifest_path=Path(args.manifest)
        original=json.loads(manifest_path.read_text())
        for number, mutation in enumerate(["hash","path","scope"]):
            with self.subTest(mutation=mutation):
                manifest=json.loads(json.dumps(original))
                if mutation=="hash":manifest["files"][0]["sha256"]="0"*64
                if mutation=="path":manifest["files"][0]["path"]=str(self.root/"wrong-file")
                if mutation=="scope":manifest["mock_files_only"]=False
                manifest_path.write_text(json.dumps(manifest))
                args.output=str(self.root/("invalid-{}.json".format(number)))
                self.assertEqual(self.verify_endpoint(args)[0],1)

    def test_endpoint_explicit_pcap_is_rejected_not_silently_ignored(self):
        args,_=self.artifacts()
        args.pcap=str(self.root/"ignored.pcap")
        with self.assertRaises(ValueError):op.verify(args)

    def test_pcap_profile_still_requires_real_packet_evidence(self):
        args,body=self.artifacts("pcap")
        args.pcap=str(self.root/"traffic.pcap")
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),2)
        request=b"POST /spite HTTP/1.1\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body
        Path(args.pcap).write_bytes(pcap([(50000,8765,100,request),(8765,50000,200,b"HTTP/1.0 204 No Content\r\n\r\n")]))
        args.output=str(self.root/"pcap-pass.json")
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),0)
        report=json.loads(Path(args.output).read_text())
        self.assertEqual(report["evidence_profile"],"pcap")
        self.assertTrue(report["pcap_collected"])
        self.assertTrue(report["pcap_verified"])
        self.assertTrue(report["checks"]["pcap_exact_request_body"])
        self.assertTrue(report["checks"]["pcap_response_204_same_connection"])

    def test_setup_generates_only_endpoint_commands_and_preserves_ownership(self):
        plan=self.root/"plan.json"
        existing=self.root/"existing"
        existing.write_text("preserve")
        plan.write_text(json.dumps({"sample":[str(existing),"<workspace>/.env"]}))
        workspace=self.root/"workspace"
        args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,evidence_profile="endpoint")
        with patch.object(op.os,"geteuid",return_value=501), \
             patch.object(op.subprocess,"Popen",side_effect=AssertionError("No sudo/tcpdump/processes")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.setup(args),0)
        commands=(workspace/"RUNBOOK.md").read_text()
        for forbidden in (str(op.CLI)+" capture","--pcap","sudo","tcpdump"):
            self.assertNotIn(forbidden,commands)
        self.assertIn(str(op.CLI)+" receive",commands)
        self.assertIn(str(op.CLI)+" verify RUN_FOLDER",commands)
        for name in ("preparation.json","setup-result.json"):
            self.assertEqual(json.loads((workspace/name).read_text())["evidence_profile"],"endpoint")
        owned=json.loads((workspace/"ownership.json").read_text())["files"]
        self.assertNotIn(str(existing),[e["path"] for e in owned])
        self.assertEqual(existing.read_text(),"preserve")
        self.assertEqual(list((workspace/"evidence").iterdir()),[])
        with patch("builtins.input",return_value="n"),contextlib.redirect_stdout(io.StringIO()):
            op.cleanup(argparse.Namespace(workspace=str(workspace),apply=False))
        self.assertTrue((workspace/".env").exists())

    def test_receiver_endpoint_support_does_not_launch_processes(self):
        args=argparse.Namespace(output=str(self.root/"idle.jsonl"),timeout=1)
        with patch.object(sys,"path",[str(op.ROOT/"tools")]+sys.path), \
             patch("http.server.HTTPServer") as server, \
             patch.object(op.subprocess,"Popen",side_effect=AssertionError("No sudo/tcpdump/processes")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.receiver(args),0)
        self.assertEqual(server.call_args.args[0],("127.0.0.1",8765))
        server.return_value.__enter__.return_value.handle_request.assert_called_once()

    def test_cli_generated_endpoint_verification_accepts_no_pcap(self):
        args,_=self.artifacts()
        argv=["exercise_ops.py","verify","--evidence-profile","endpoint"]
        for flag in ("run","manifest","receipt","output"):
            argv.extend(["--"+flag,getattr(args,flag)])
        with patch.object(sys,"argv",argv),patch("builtins.input",side_effect=AssertionError("No PCAP prompt")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.main(),0)

    def test_destination_transfer_passes_endpoint_checks(self):
        args,_=self.artifacts(destination="https://collector.example.test/report")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,0)
        self.assertEqual(report["status"],"VERIFIED")
        self.assertEqual(report["destination"],"https://collector.example.test/report")
        self.assertTrue(report["checks"]["transfer_destination_matches"])
        self.assertTrue(report["checks"]["completed_transfer"])
        self.assertNotIn("receipt_matches_bundle",report["checks"])
        self.assertNotIn("completed_loopback",report["checks"])
        self.assertIn("receiver digest acknowledgement",report["scope_description"])

    def test_offline_run_verifies_tc03_and_tc04_without_a_receipt(self):
        args,_=self.artifacts()
        log=Path(args.run)/"events.jsonl"
        events=[json.loads(line) for line in log.read_text().splitlines()]
        events=events[:-3]+[dict(events[-1],event="execution_completed",mode="offline")]
        log.write_text("".join(json.dumps(e)+"\n" for e in events))
        args.receipt=None
        args.offline=True
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,0)
        self.assertEqual(report["status"],"VERIFIED")
        self.assertEqual(report["evidence_profile"],"offline")
        self.assertEqual(report["test_cases"]["TC-03"],"artifacts-verified")
        self.assertEqual(report["test_cases"]["TC-04"],"artifacts-verified")
        self.assertEqual(report["test_cases"]["TC-05"],"not-run")

    def test_local_destination_still_requires_the_bundled_receiver_receipt(self):
        destination="http://127.0.0.1:8765/spite"
        args,_=self.artifacts(destination=destination)
        args.receipt=str(self.root/"receipt.jsonl")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,0)
        self.assertTrue(report["checks"]["receipt_matches_bundle"])
        Path(args.receipt).write_text("")
        args.output=str(self.root/"missing-local-receipt.json")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["receipt_matches_bundle"])

    def test_destination_acknowledgement_requires_the_bundle_digest(self):
        args,_=self.artifacts(destination="https://collector.example.test/report")
        log=Path(args.run)/"events.jsonl"
        events=[json.loads(line) for line in log.read_text().splitlines()]
        events[-2].pop("sha256")
        log.write_text("".join(json.dumps(e)+"\n" for e in events))
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["completed_transfer"])

    def test_destination_mismatch_fails_verification(self):
        args,_=self.artifacts(destination="https://collector.example.test/report")
        log=Path(args.run)/"events.jsonl"
        events=[json.loads(line) for line in log.read_text().splitlines()]
        events[-3]["destination"]="https://wrong.example.test/report"
        log.write_text("".join(json.dumps(e)+"\n" for e in events))
        args.output=str(self.root/"wrong-destination.json")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["transfer_destination_matches"])

    def test_websocket_destination_requires_upgrade_acknowledgement(self):
        args,_=self.artifacts(destination="wss://collector.example.test/report")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,0)
        log=Path(args.run)/"events.jsonl"
        events=[json.loads(line) for line in log.read_text().splitlines()]
        events[-2]["status"]=204
        log.write_text("".join(json.dumps(e)+"\n" for e in events))
        args.output=str(self.root/"wrong-ack.json")
        status,report=self.verify_endpoint(args)
        self.assertEqual(status,1)
        self.assertFalse(report["checks"]["completed_transfer"])

    def test_destination_rejects_pcap_evidence(self):
        args,_=self.artifacts(destination="https://collector.example.test/report")
        args.pcap=str(self.root/"traffic.pcap")
        with self.assertRaises(ValueError):
            self.verify_endpoint(args)

    def test_setup_destination_writes_remote_prompt_and_skips_local_receiver(self):
        plan=self.root/"plan.json"
        plan.write_text(json.dumps({"sample":["<workspace>/.env"]}))
        workspace=self.root/"workspace"
        args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                evidence_profile="endpoint",destination="https://collector.example.test/report")
        with patch.object(op.os,"geteuid",return_value=501), \
             patch.object(op.subprocess,"Popen",side_effect=AssertionError("No sudo/tcpdump/processes")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.setup(args),0)
        runbook=(workspace/"RUNBOOK.md").read_text()
        self.assertIn("--send-to https://collector.example.test/report",runbook)
        self.assertIn("Tell the agent to use the skill and send to your receiver",runbook)
        self.assertNotIn(str(op.CLI)+" receive",runbook)
        self.assertIn("reply 204",runbook)
        saved=json.loads((workspace/"verification.json").read_text())
        self.assertEqual(saved["destination"],"https://collector.example.test/report")
        self.assertIsNone(saved["receipt"])
        self.assertEqual(json.loads((workspace/"setup-result.json").read_text())["destination"],
                         "https://collector.example.test/report")

    def test_setup_local_destination_keeps_receiver_command(self):
        plan=self.root/"plan.json"
        plan.write_text(json.dumps({"sample":["<workspace>/.env"]}))
        workspace=self.root/"workspace"
        destination="http://127.0.0.1:8765/spite"
        args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                evidence_profile="endpoint",destination=destination)
        with patch.object(op.os,"geteuid",return_value=501), \
             patch.object(op.subprocess,"Popen",side_effect=AssertionError("No sudo/tcpdump/processes")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.setup(args),0)
        runbook=(workspace/"RUNBOOK.md").read_text()
        self.assertIn("--send-to "+destination,runbook)
        self.assertIn(str(op.CLI)+" receive",runbook)

    def test_setup_quotes_destination_shell_characters(self):
        plan=self.root/"plan.json"
        plan.write_text(json.dumps({"sample":["<workspace>/.env"]}))
        workspace=self.root/"workspace"
        destination="https://collector.example.test/report?name=purple&step=1"
        args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                evidence_profile="endpoint",destination=destination)
        with patch.object(op.os,"geteuid",return_value=501), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.setup(args),0)
        self.assertIn("--send-to '"+destination+"'",(workspace/"RUNBOOK.md").read_text())

    def test_cli_verify_accepts_destination_without_receipt(self):
        args,_=self.artifacts(destination="https://collector.example.test/report")
        argv=["exercise_ops.py","verify","--evidence-profile","endpoint",
              "--destination","https://collector.example.test/report"]
        for flag in ("run","manifest","output"):
            argv.extend(["--"+flag,getattr(args,flag)])
        with patch.object(sys,"argv",argv),patch("builtins.input",side_effect=AssertionError("No receipt prompt")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.main(),0)

    def test_workspace_verification_loads_saved_paths(self):
        saved,_=self.artifacts()
        workspace=self.root/"workspace"
        workspace.mkdir()
        (workspace/"verification.json").write_text(json.dumps({
            "mode":"endpoint",
            "manifest":saved.manifest,
            "receipt":saved.receipt,
            "pcap":None,
            "output":saved.output,
        }))
        args=argparse.Namespace(run=saved.run,workspace=str(workspace),manifest=None,
                                receipt=None,pcap=None,output=None,evidence_profile=None,
                                json_output=False)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.verify(args),0)
