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
