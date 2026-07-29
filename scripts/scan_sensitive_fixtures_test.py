#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

module_path = Path(__file__).with_name("scan_sensitive_fixtures.py")
module_spec = importlib.util.spec_from_file_location("scan_sensitive_fixtures", module_path)
assert module_spec is not None and module_spec.loader is not None
scanner = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(scanner)


class SensitiveFixtureScannerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="opswarden-scanner-")
        root = Path(self.temporary.name).resolve()
        self.root = root
        self.runtime = root / "runtime"
        self.artifacts = root / "artifacts"
        self.pattern = root / "patterns"
        self.repo = Path(__file__).resolve().parent.parent
        patterns = [f"SCANNER_SECRET_{index:02d}_UNIQUE".encode() for index in range(16)]
        self.secret = patterns[0]
        self.pattern.write_bytes(b"\n".join(patterns) + b"\n")
        self.pattern.chmod(0o600)
        self.targets = [
            self.runtime / "data" / "opswarden.db",
            self.runtime / "data" / "opswarden.db-wal",
            self.runtime / "data" / "opswarden.db-shm",
            self.runtime / "backups" / "scheduled.sqlite3",
            self.artifacts / "backups" / "online-backup.sqlite3",
            self.artifacts / "logs" / "application.log",
            self.artifacts / "logs" / "restore-compose.log",
            self.artifacts / "audit" / "audit-export.json",
            self.artifacts / "browser" / "browser-storage.json",
            self.artifacts / "errors" / "captured-errors.json",
            self.artifacts / "playwright" / "test-results" / "residual.txt",
        ]
        for target in self.targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"safe artifact\n")
        os.environ.update(
            {
                "OPSWARDEN_E2E_REPO_ROOT": str(self.repo),
                "OPSWARDEN_E2E_RUNTIME_DIR": str(self.runtime),
                "OPSWARDEN_E2E_ARTIFACT_DIR": str(self.artifacts),
                "OPSWARDEN_E2E_SECRET_FILE": str(self.pattern),
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_scan(self) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return scanner.main()

    def test_clean_fixture_and_every_artifact_class_negative_control(self) -> None:
        self.assertEqual(self.run_scan(), 0)
        for target in self.targets:
            original = target.read_bytes()
            target.write_bytes(original + self.secret)
            self.assertEqual(
                self.run_scan(),
                1,
                f"scanner false negative for {target.relative_to(self.root)}",
            )
            target.write_bytes(original)

    def test_compressed_playwright_output_negative_control(self) -> None:
        archive = self.artifacts / "playwright" / "test-results" / "trace.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("trace/network-body.txt", self.secret)
        self.assertEqual(self.run_scan(), 1)

    def test_pattern_file_requires_private_mode(self) -> None:
        self.pattern.chmod(0o644)
        self.assertEqual(self.run_scan(), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
