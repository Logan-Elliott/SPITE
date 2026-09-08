import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/seed_credentials.py"
spec = importlib.util.spec_from_file_location("seeder", SCRIPT)
seeder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seeder)


class SeederTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_creates_missing_parents_and_private_mock_file(self):
        target = self.root / ".aws/credentials"
        self.assertEqual(seeder.seed_file(target), "created")
        self.assertEqual(target.read_bytes(), seeder.MOCK_DATA)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)

    def test_existing_content_and_metadata_untouched(self):
        target = self.root / "existing"
        target.write_bytes(b"existing credential")
        before = target.stat()
        self.assertEqual(seeder.seed_file(target), "skipped_exists")
        after = target.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_mode),
                         (after.st_ino, after.st_mtime_ns, after.st_mode))
        self.assertEqual(target.read_bytes(), b"existing credential")

    def test_existing_directory_and_dangling_symlink_skipped(self):
        self.assertEqual(seeder.seed_file(self.root), "skipped_exists")
        target = self.root / "link"
        target.symlink_to(self.root / "absent")
        self.assertEqual(seeder.seed_file(target), "skipped_exists")
        self.assertTrue(target.is_symlink())
        self.assertFalse((self.root / "absent").exists())

    def test_parent_symlink_rejected(self):
        (self.root / "actual").mkdir()
        (self.root / "link").symlink_to(self.root / "actual")
        with self.assertRaises(OSError):
            seeder.seed_file(self.root / "link/credential")
        self.assertFalse((self.root / "actual/credential").exists())

    def test_racing_creator_is_not_overwritten(self):
        target = self.root / "raced"
        original_open = os.open

        def racing_open(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                target.write_bytes(b"created by another process")
            return original_open(path, flags, *args, **kwargs)

        with patch.object(seeder.os, "open", side_effect=racing_open):
            self.assertEqual(seeder.seed_file(target), "skipped_exists")
        self.assertEqual(target.read_bytes(), b"created by another process")

    def test_invalid_paths_rejected(self):
        for target in ["relative", str(self.root / "*.env"), str(self.root) + "/../file"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                seeder.seed_file(target)


if __name__ == "__main__":
    unittest.main()
