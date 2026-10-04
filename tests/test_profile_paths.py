import base64
import contextlib
import importlib.util
import io
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


class EnvClean(unittest.TestCase):
    def setUp(self):
        os.environ.pop("XDG_CONFIG_HOME", None)


class ResolveTests(EnvClean):
    def test_synthetic_and_real_use_the_same_discovered_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            chrome = chromium_profile(home / ".config/google-chrome", login=False)
            trae = home / ".config/Trae/User/globalStorage"
            trae.mkdir(parents=True)
            workspace = home / "workspace"
            for source in ("synthetic", "real"):
                self.assertEqual(profile_paths.resolve("<chrome-profile>/Login Data", workspace, source, home=home),
                                 chrome / "Login Data")
                self.assertEqual(profile_paths.resolve("<trae-storage>/state.vscdb", workspace, source, home=home),
                                 trae / "state.vscdb")
                self.assertEqual(profile_paths.resolve("<workspace>/config/secrets.json", workspace, source, home=home),
                                 workspace / "config/secrets.json")

    def test_unknown_placeholder_is_rejected(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("<mystery>/x", Path("/tmp/ws"), "synthetic", home=Path("/home/nobody"))

    def test_placeholder_must_start_the_path(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("~/Library/<chrome-profile>/Login Data", Path("/tmp/ws"), "synthetic",
                                  home=Path("/home/nobody"))


class DiscoverTests(EnvClean):
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

    def test_browser_support_directories_are_not_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            (home / ".config/google-chrome/Crashpad").mkdir(parents=True)
            (home / ".mozilla/firefox/Crash Reports").mkdir(parents=True)
            self.assertIsNone(profile_paths.discover("chrome-profile", home))
            self.assertIsNone(profile_paths.discover("firefox-profile", home))

    def test_chromium_honors_xdg_config_home(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            xdg = root / "xdg"
            wanted = chromium_profile(xdg / "chromium", "Default")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
                self.assertEqual(profile_paths.discover("chrome-profile", root / "home"), wanted)

    def test_chromium_finds_a_snap_chromium_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = chromium_profile(home / "snap/chromium/common/chromium", "Default")
            self.assertEqual(profile_paths.discover("chrome-profile", home), wanted)

    def test_chromium_finds_a_flatpak_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = chromium_profile(home / ".var/app/com.google.Chrome/config/google-chrome", "Default")
            self.assertEqual(profile_paths.discover("chrome-profile", home), wanted)

    def test_trae_storage_honors_xdg_config_home(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            xdg = root / "xdg"
            wanted = xdg / "Trae/User/globalStorage"
            wanted.mkdir(parents=True)
            (wanted / "state.vscdb").write_bytes(b"sqlite")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
                self.assertEqual(profile_paths.discover("trae-storage", root / "home"), wanted)

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

    def test_missing_product_resolves_to_none_in_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            for source in ("synthetic", "real"):
                self.assertIsNone(profile_paths.resolve("<chrome-profile>/Login Data", Path("/tmp/ws"), source, home=home))


class PreparePlaceholderTests(EnvClean):
    def test_synthetic_creates_missing_leaves_in_discovered_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            chrome = chromium_profile(home / ".config/google-chrome", login=False)
            firefox = home / ".mozilla/firefox/abc.default-release"
            firefox.mkdir(parents=True)
            trae = home / ".config/Trae/User/globalStorage"
            trae.mkdir(parents=True)
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": ["<chrome-profile>/Login Data", "<firefox-profile>/logins.json",
                               "<trae-storage>/state.vscdb"]}
            with patch.dict(os.environ, {"HOME": str(home)}):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="synthetic")
            self.assertFalse(failed)
            manifest = json.loads((root / "out/sample.json").read_text())
            targets = [chrome / "Login Data", firefox / "logins.json", trae / "state.vscdb"]
            self.assertEqual([entry["path"] for entry in manifest["files"]], [str(path) for path in targets])
            for path in targets:
                self.assertEqual(path.read_bytes(), prepare_batches.MOCK_DATA)
            self.assertEqual(summary["sample"]["created"], 3)
            self.assertFalse((home / ".spite-exercise").exists())
            runner = prepare_batches.load_runner()
            run = root / "run"
            run.mkdir()
            with patch.object(runner.tempfile, "mkdtemp", return_value=str(run)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(root / "out/sample.json"), 0)
            payload = json.loads(base64.b64decode((run / "diagnostics.b64").read_bytes()))
            for path in targets:
                self.assertEqual(base64.b64decode(payload["credentials"][str(path)]),
                                 prepare_batches.MOCK_DATA)
            with patch.dict(os.environ, {"HOME": str(home)}):
                real_summary, real_failed = prepare_batches.prepare(plan, workspace, root / "real", source="real")
            self.assertFalse(real_failed)
            self.assertEqual(real_summary["sample"]["collected"], 3)
            real_manifest = json.loads((root / "real/sample.json").read_text())
            self.assertEqual([entry["path"] for entry in real_manifest["files"]], [str(path) for path in targets])

    def test_synthetic_skips_an_existing_leaf_without_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            profile = chromium_profile(home / ".config/google-chrome")
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": ["<chrome-profile>/Login Data"]}
            with patch.dict(os.environ, {"HOME": str(home)}):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="synthetic")
            self.assertFalse(failed)
            self.assertEqual((profile / "Login Data").read_bytes(), b"chrome login")
            self.assertEqual(summary["sample"]["skipped_exists"], 1)
            self.assertIsNone(summary["sample"]["manifest"])

    def test_synthetic_records_missing_profiles_as_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": ["<chrome-profile>/Login Data", "<firefox-profile>/logins.json"]}
            with patch.dict(os.environ, {"HOME": str(home)}):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="synthetic")
            self.assertFalse(failed)
            self.assertEqual(summary["sample"]["unavailable"], 2)
            self.assertIsNone(summary["sample"]["manifest"])
            self.assertFalse((root / "out/sample.json").exists())
            events = [json.loads(line) for line in (root / "out/seeding.jsonl").read_text().splitlines()]
            self.assertEqual([event["event"] for event in events], ["unavailable", "unavailable"])
            self.assertEqual([event["path"] for event in events], plan["sample"])
            self.assertFalse(home.exists())

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
