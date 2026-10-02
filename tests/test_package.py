import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_operator import op


class CombinedSetupTests(unittest.TestCase):
    def test_combined_manifest_and_independent_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            plan=root/"plan.json"
            plan.write_text(json.dumps({"one":["<workspace>/first"],"two":["<workspace>/second"]}))
            workspace=root/"workspace"
            with patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True)),0)
            combined=json.loads((workspace/"all-prepared.json").read_text())
            self.assertEqual(len(combined["files"]),2)
            ledger=json.loads((workspace/"ownership.json").read_text())
            self.assertEqual(sum(e["kind"]=="seed" for e in ledger["files"]),2)
            self.assertEqual(list((workspace/"evidence").iterdir()),[])
            commands=(workspace/"OPERATOR-COMMANDS.txt").read_text()
            self.assertIn("HTTP-Receiver.command",commands)
            self.assertIn("Packet-Capture.command",commands)
            self.assertIn("Verify.command",commands)
            self.assertNotIn("preflight.py",commands)

    def test_custom_target_profile_controls_install_path_and_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            plan=root/"plan.json"
            plan.write_text(json.dumps({"sample":["<workspace>/fixture"]}))
            profile=root/"target.json"
            profile.write_text(json.dumps({
                "schema_version":1,
                "id":"example-agent",
                "display_name":"Example Agent",
                "skill_name":"agent-workspace-preflight",
                "install_path":".example/skills/agent-workspace-preflight",
            }))
            workspace=root/"workspace"
            args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                    target_profile=str(profile),evidence_profile="endpoint")
            with patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(args),0)
            self.assertTrue((workspace/".example/skills/agent-workspace-preflight/SKILL.md").is_file())
            prompts=(workspace/"AGENT-PROMPTS.txt").read_text()
            self.assertIn("Use the agent-workspace-preflight skill",prompts)
            self.assertIn("T2 explicit offline",prompts)
            self.assertIn("T3 implicit selection",prompts)
            self.assertIn("T4 loopback",prompts)
            result=json.loads((workspace/"setup-result.json").read_text())
            self.assertEqual(result["target_profile"],"example-agent")
            self.assertEqual(result["target_display_name"],"Example Agent")
            self.assertEqual(json.loads((workspace/"target-profile.json").read_text())["install_path"],
                             ".example/skills/agent-workspace-preflight")

    def test_target_profile_rejects_traversal_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            profile=Path(directory)/"target.json"
            base={"schema_version":1,"id":"example-agent","display_name":"Example Agent",
                  "skill_name":"agent-workspace-preflight",
                  "install_path":"../agent-workspace-preflight"}
            profile.write_text(json.dumps(base))
            with self.assertRaises(ValueError):
                op.load_target_profile(profile)
            base["install_path"]=".agent/skills/agent-workspace-preflight"
            base["skill_name"]="different-skill"
            profile.write_text(json.dumps(base))
            with self.assertRaises(ValueError):
                op.load_target_profile(profile)
            base["skill_name"]="agent-workspace-preflight"
            base["unexpected"]=True
            profile.write_text(json.dumps(base))
            with self.assertRaises(ValueError):
                op.load_target_profile(profile)
