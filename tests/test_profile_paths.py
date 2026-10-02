import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

with patch.object(sys, "path", [str(ROOT / "tools")] + sys.path):
    import profile_paths
    spec = importlib.util.spec_from_file_location("profile_prepare", ROOT / "tools/prepare_batches.py")
    prepare_batches = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare_batches)


def chromium_profile(root, profile="Default", login=True):
    directory = root / profile
    directory.mkdir(parents=True, exist_ok=True)
    if login:
        (directory / "Login Data").write_bytes(b"chrome login")
    return directory


class ResolveTests(unittest.TestCase):
    def test_synthetic_maps_placeholders_to_isolated_absolute_dirs(self):
        workspace = Path("/tmp/ws")
        home = Path("/home/nobody")
        self.assertEqual(profile_paths.resolve("<chrome-profile>/Login Data", workspace, "synthetic", home=home),
                         home / ".asrt-exercise/chrome/Login Data")
        self.assertEqual(profile_paths.resolve("<trae-storage>/state.vscdb", workspace, "synthetic", home=home),
                         home / ".asrt-exercise/trae/state.vscdb")
        self.assertEqual(profile_paths.resolve("<workspace>/config/secrets.json", workspace, "synthetic", home=home),
                         workspace / "config/secrets.json")

    def test_unknown_placeholder_is_rejected(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("<mystery>/x", Path("/tmp/ws"), "synthetic", home=Path("/home/nobody"))

    def test_placeholder_must_start_the_path(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("~/Library/<chrome-profile>/Login Data", Path("/tmp/ws"), "synthetic",
                                  home=Path("/home/nobody"))


class DiscoverTests(unittest.TestCase):
    def test_chromium_prefers_a_profile_that_holds_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            chromium_profile(home / ".config/google-chrome", "Default", login=False)
            wanted = chromium_profile(home / ".config/google-chrome", "Profile 1", login=True)
            self.assertEqual(profile_paths.discover("chrome-profile", home), wanted)

    def test_chromium_reads_the_macos_location(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = chromium_profile(home / "Library/Application Support/Google/Chrome", "Default")
            self.assertEqual(profile_paths.discover("chrome-profile", home), wanted)

    def test_firefox_reads_a_linux_profiles_ini(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / ".mozilla/firefox"
            wanted = root / "abc123.default"
            wanted.mkdir(parents=True)
            (root / "profiles.ini").write_text(
                "[Profile0]\nName=default\nPath=abc123.default\nDefault=1\n")
            self.assertEqual(profile_paths.discover("firefox-profile", home), wanted)

    def test_firefox_reads_a_snap_profile_without_ini(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = home / "snap/firefox/common/.mozilla/firefox/zz.default-release"
            wanted.mkdir(parents=True)
            self.assertEqual(profile_paths.discover("firefox-profile", home), wanted)

    def test_trae_storage_is_found_on_linux(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = home / ".config/Trae/User/globalStorage"
            wanted.mkdir(parents=True)
            (wanted / "state.vscdb").write_bytes(b"sqlite")
            self.assertEqual(profile_paths.discover("trae-storage", home), wanted)

    def test_missing_product_resolves_to_none_in_real_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            self.assertIsNone(profile_paths.resolve("<chrome-profile>/Login Data", Path("/tmp/ws"), "real", home=home))


class PreparePlaceholderTests(unittest.TestCase):
    def test_synthetic_creates_the_isolated_profile_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": ["<chrome-profile>/Login Data"]}
            with patch.dict(os.environ, {"HOME": str(root / "home")}):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="synthetic")
            self.assertFalse(failed)
            manifest = json.loads((root / "out/sample.json").read_text())
            self.assertEqual(manifest["files"][0]["path"],
                             str(root / "home/.asrt-exercise/chrome/Login Data"))

    def test_real_selects_discovered_profile_and_records_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            wanted = chromium_profile(home / ".config/google-chrome", "Default")
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": [
                "<chrome-profile>/Login Data",
                "<brave-profile>/Login Data",
            ]}
            with patch.dict(os.environ, {"HOME": str(home)}):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="real")
            self.assertFalse(failed)
            manifest = json.loads((root / "out/sample.json").read_text())
            self.assertEqual([e["path"] for e in manifest["files"]], [str(wanted / "Login Data")])
            self.assertEqual((summary["sample"]["collected"], summary["sample"]["unresolved"]), (1, 1))

    def test_real_reports_files_over_the_size_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            profile = home / ".config/google-chrome/Default"
            profile.mkdir(parents=True)
            (profile / "small").write_bytes(b"x" * (100 * 1024))
            (profile / "huge").write_bytes(b"y" * (9 * 1024 * 1024))
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": [str(profile / "small"), str(profile / "huge")]}
            with patch.dict(os.environ, {"HOME": str(home)}):
                summary, _ = prepare_batches.prepare(plan, workspace, root / "out", source="real")
            self.assertEqual((summary["sample"]["collected"], summary["sample"]["unusable"]), (1, 1))

    def test_real_reports_files_over_the_total_harvest_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "data"
            profile.mkdir()
            (profile / "one").write_bytes(b"a" * (5 * 1024 * 1024))
            (profile / "two").write_bytes(b"b" * (5 * 1024 * 1024))
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": [str(profile / "one"), str(profile / "two")]}
            summary, _ = prepare_batches.prepare(plan, workspace, root / "out", source="real")
            self.assertEqual((summary["sample"]["collected"], summary["sample"]["oversize"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
