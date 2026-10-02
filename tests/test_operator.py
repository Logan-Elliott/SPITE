import argparse
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
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
            mock=root/"mock";mock.write_bytes(b"ASRT-001 mock")
            manifest=root/"manifest.json"
            manifest.write_text(json.dumps(dict(exercise="ASRT-001",mock_files_only=True,
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
            headers=b"POST /asrt HTTP/1.1\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"
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
            # Application mismatch must not be disguised as an empty-capture issue.
            receipt.write_text(json.dumps(dict(event="collector_received",run_id=payload["run_id"]))+"\n")
            args.output=str(root/"bad-receipt.json")
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(op.verify(args),1)


if __name__=="__main__":unittest.main()
