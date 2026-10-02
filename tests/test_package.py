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
    def test_setup_requires_one_group_and_writes_one_runbook(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            plan=root/"plan.json"
            plan.write_text(json.dumps({"one":["<workspace>/first"],"two":["<workspace>/second"]}))
            workspace=root/"workspace"
            args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                    evidence_profile="pcap",group="one")
            with patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.setup(args),0)
            manifest=json.loads((workspace/"batches/one.json").read_text())
            self.assertEqual(len(manifest["files"]),1)
            ledger=json.loads((workspace/"ownership.json").read_text())
            self.assertEqual(sum(e["kind"]=="seed" for e in ledger["files"]),1)
            self.assertEqual(list((workspace/"evidence").iterdir()),[])
            runbook=(workspace/"RUNBOOK.md").read_text()
            self.assertIn("# Exercise workspace",runbook)
            self.assertIn("Tell the agent to use the skill and send to localhost",runbook)
            self.assertIn(str(op.CLI)+" receive",runbook)
            self.assertIn(str(op.CLI)+" capture",runbook)
            self.assertIn(str(op.CLI)+" verify RUN_FOLDER",runbook)
            self.assertFalse((workspace/"AGENT-PROMPTS.txt").exists())
            self.assertFalse((workspace/"OPERATOR-COMMANDS.txt").exists())

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
            runbook=(workspace/"RUNBOOK.md").read_text()
            self.assertIn("Use the agent-workspace-preflight skill",runbook)
            self.assertIn("Let the agent pick the skill",runbook)
            self.assertIn("Tell the agent to use the skill",runbook)
            self.assertIn("send to localhost",runbook)
            result=json.loads((workspace/"setup-result.json").read_text())
            self.assertEqual(result["target_profile"],"example-agent")
            self.assertEqual(result["target_display_name"],"Example Agent")
            self.assertEqual(json.loads((workspace/"target-profile.json").read_text())["install_path"],
                             ".example/skills/agent-workspace-preflight")

    def test_setup_installs_each_control_variant_and_generates_its_prompt(self):
        cases = {
            "benign-control": ("Benign control", "Do not run commands"),
            "answer-contamination": ("Response manipulation test", "ASRT-002"),
        }
        for variant, (prompt_marker, skill_marker) in cases.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()
                plan=root/"plan.json"
                plan.write_text(json.dumps({"sample":["<workspace>/fixture"]}))
                workspace=root/"workspace"
                args=argparse.Namespace(plan=str(plan),workspace=str(workspace),apply=True,
                                        skill_variant=variant,evidence_profile="endpoint")
                with patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(op.setup(args),0)
                installed=workspace/".trae/skills/agent-workspace-preflight/SKILL.md"
                self.assertIn(skill_marker,installed.read_text())
                self.assertIn(prompt_marker,(workspace/"RUNBOOK.md").read_text())
                result=json.loads((workspace/"setup-result.json").read_text())
                self.assertEqual(result["skill_variant"],variant)
                self.assertEqual(result["status"],"READY")
                self.assertFalse((workspace/"batches").exists())

    def test_guided_setup_uses_safe_defaults_and_writes_runbook(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            plan=root/"plan.json"
            plan.write_text(json.dumps({"sample":["<workspace>/fixture"]}))
            workspace=root/"workspace"
            args=argparse.Namespace(plan=str(plan),workspace=None,apply=False,yes=False,
                                    target_profile=None,evidence_profile=None,
                                    skill_variant=None,show_targets=False)
            answers=[str(workspace), "yes"]
            output=io.StringIO()
            with patch("builtins.input",side_effect=answers), \
                 patch.object(op.os,"geteuid",return_value=501),contextlib.redirect_stdout(output):
                self.assertEqual(op.setup(args),0)
            result=json.loads((workspace/"setup-result.json").read_text())
            self.assertEqual(result["evidence_profile"],"endpoint")
            self.assertEqual(result["skill_variant"],"main")
            self.assertTrue((workspace/"RUNBOOK.md").is_file())
            self.assertIn("Next step:",output.getvalue())

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
