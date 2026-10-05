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

    def test_existing_profile_wins_over_the_synthetic_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            wanted = chromium_profile(home / ".config/google-chrome", "Profile 2")
            path = profile_paths.resolve("<chrome-profile>/Login Data", home / "workspace", "synthetic",
                                         home=home, platform="darwin")
            self.assertEqual(path, wanted / "Login Data")

    def test_profile_discovery_error_falls_back_only_for_synthetic(self):
        home = Path("/home/operator")
        workspace = Path("/tmp/workspace")
        with patch.object(profile_paths, "discover", side_effect=PermissionError("blocked")):
            self.assertEqual(
                profile_paths.resolve("<chrome-profile>/Login Data", workspace, "synthetic",
                                      home=home, platform="linux"),
                home / ".config/google-chrome/Default/Login Data",
            )
            self.assertIsNone(profile_paths.resolve(
                "<chrome-profile>/Login Data", workspace, "real", home=home, platform="linux"))

    def test_unknown_placeholder_is_rejected(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("<mystery>/x", Path("/tmp/ws"), "synthetic", home=Path("/home/nobody"))

    def test_placeholder_must_start_the_path(self):
        with self.assertRaises(ValueError):
            profile_paths.resolve("~/Library/<chrome-profile>/Login Data", Path("/tmp/ws"), "synthetic",
                                  home=Path("/home/nobody"))


class UsualProfileTests(EnvClean):
    def test_macos_paths_use_the_normal_product_folders(self):
        home = Path("/Users/operator")
        expected = {
            "chrome-profile": home / "Library/Application Support/Google/Chrome/Default",
            "brave-profile": home / "Library/Application Support/BraveSoftware/Brave-Browser/Default",
            "edge-profile": home / "Library/Application Support/Microsoft Edge/Default",
            "firefox-profile": home / "Library/Application Support/Firefox/Profiles/spite.default-release",
            "trae-storage": home / "Library/Application Support/Trae/User/globalStorage",
            "openclaw-config": home / ".config/openclaw",
            "openclaw-home": home / ".openclaw",
        }
        for name, wanted in expected.items():
            with self.subTest(name=name):
                self.assertEqual(profile_paths.usual_profile(name, home, platform="darwin"), wanted)

    def test_linux_paths_respect_xdg_config_home(self):
        home = Path("/home/operator")
        config = Path("/mnt/operator-config")
        expected = {
            "chrome-profile": config / "google-chrome/Default",
            "brave-profile": config / "BraveSoftware/Brave-Browser/Default",
            "edge-profile": config / "microsoft-edge/Default",
            "firefox-profile": home / ".mozilla/firefox/spite.default-release",
            "trae-storage": config / "Trae/User/globalStorage",
            "openclaw-config": config / "openclaw",
            "openclaw-home": home / ".openclaw",
        }
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config)}):
            for name, wanted in expected.items():
                with self.subTest(name=name):
                    self.assertEqual(profile_paths.usual_profile(name, home, platform="linux"), wanted)


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

    def test_firefox_does_not_follow_a_symlinked_profiles_ini(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / ".mozilla/firefox"
            redirected = root / "redirected.default"
            redirected.mkdir(parents=True)
            fallback = root / "Profiles/abc123.default-release"
            fallback.mkdir(parents=True)
            target = home / "redirected-profiles.ini"
            target.write_text(
                "[Profile0]\nName=redirected\nPath=redirected.default\nDefault=1\n")
            ini = root / "profiles.ini"
            ini.symlink_to(target)

            original_open = os.open
            opened = []

            def record_open(path, flags, *args, **kwargs):
                opened.append((os.fspath(path), flags, kwargs.get("dir_fd")))
                return original_open(path, flags, *args, **kwargs)

            with patch.object(profile_paths.os, "open", side_effect=record_open):
                found = profile_paths.discover("firefox-profile", home)

            self.assertEqual(found, fallback)
            self.assertEqual(opened[-1][0], ini.name)
            self.assertIsNotNone(opened[-1][2])
            self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in opened))

    def test_firefox_does_not_follow_a_symlinked_profiles_ini_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            actual = home / "actual-firefox"
            redirected = actual / "redirected.default"
            redirected.mkdir(parents=True)
            (actual / "profiles.ini").write_text(
                "[Profile0]\nName=redirected\nPath=redirected.default\nDefault=1\n")
            linked_parent = home / "linked-firefox"
            linked_parent.symlink_to(actual, target_is_directory=True)

            with self.assertRaises(OSError):
                profile_paths._read_ini(linked_parent / "profiles.ini")

    def test_firefox_ignores_a_fifo_profiles_ini_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / ".mozilla/firefox"
            fallback = root / "Profiles/abc123.default-release"
            fallback.mkdir(parents=True)
            ini = root / "profiles.ini"
            os.mkfifo(ini)

            original_open = os.open

            def require_nonblocking_open(path, flags, *args, **kwargs):
                if os.fspath(path) == ini.name and kwargs.get("dir_fd") is not None:
                    self.assertTrue(flags & os.O_NONBLOCK)
                return original_open(path, flags, *args, **kwargs)

            with patch.object(profile_paths.os, "open", side_effect=require_nonblocking_open):
                found = profile_paths.discover("firefox-profile", home)

            self.assertEqual(found, fallback)

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

    def test_missing_product_uses_the_usual_folder_only_in_synthetic_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            workspace = Path("/tmp/ws")
            self.assertEqual(
                profile_paths.resolve("<chrome-profile>/Login Data", workspace, "synthetic",
                                      home=home, platform="linux"),
                home / ".config/google-chrome/Default/Login Data",
            )
            self.assertIsNone(profile_paths.resolve("<chrome-profile>/Login Data", workspace, "real",
                                                    home=home, platform="linux"))


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
            self.assertEqual(real_summary["sample"]["selected"], 3)
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

    def test_synthetic_creates_usual_profiles_when_products_are_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            workspace = root / "workspace"
            workspace.mkdir()
            plan = {"sample": ["<chrome-profile>/Login Data", "<firefox-profile>/logins.json"]}
            with patch.dict(os.environ, {"HOME": str(home)}), \
                 patch.object(profile_paths.sys, "platform", "linux"):
                summary, failed = prepare_batches.prepare(plan, workspace, root / "out", source="synthetic")
            self.assertFalse(failed)
            self.assertEqual(summary["sample"]["created"], 2)
            self.assertEqual(summary["sample"]["unavailable"], 0)
            self.assertEqual(summary["sample"]["manifest"], "sample.json")
            expected = [
                home / ".config/google-chrome/Default/Login Data",
                home / ".mozilla/firefox/spite.default-release/logins.json",
            ]
            manifest = json.loads((root / "out/sample.json").read_text())
            self.assertEqual([entry["path"] for entry in manifest["files"]],
                             [str(path) for path in expected])
            events = [json.loads(line) for line in (root / "out/seeding.jsonl").read_text().splitlines()]
            self.assertEqual([event["event"] for event in events], ["created", "created"])
            self.assertEqual([event["path"] for event in events], [str(path) for path in expected])

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
            self.assertEqual((summary["sample"]["selected"], summary["sample"]["unresolved"]), (1, 1))

    def test_real_selects_files_larger_than_the_old_per_file_limit(self):
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
            self.assertEqual((summary["sample"]["selected"], summary["sample"]["unusable"]), (2, 0))

    def test_real_selects_files_larger_than_the_old_total_limit(self):
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
            self.assertEqual((summary["sample"]["selected"], summary["sample"]["unusable"]), (2, 0))
            self.assertNotIn("oversize", summary["sample"])


if __name__ == "__main__":
    unittest.main()
