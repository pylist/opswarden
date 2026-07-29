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
from unittest import mock

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
        self.pattern = self.runtime / "sensitive-patterns"
        self.repo = Path(__file__).resolve().parent.parent
        patterns = [f"SCANNER_SECRET_{index:02d}_UNIQUE".encode() for index in range(16)]
        self.secret = patterns[0]
        self.pattern.parent.mkdir(parents=True)
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

    def test_raw_length_prefixed_mcp_failure_is_scanned(self) -> None:
        body = b"raw MCP failure: " + self.secret
        target = self.artifacts / "errors" / "mcp-failures.bin"
        target.write_bytes(len(body).to_bytes(8, "big") + body)
        target.chmod(0o600)
        self.assertEqual(self.run_scan(), 1)

    def test_pattern_file_requires_private_mode(self) -> None:
        self.pattern.chmod(0o644)
        self.assertEqual(self.run_scan(), 2)

    def test_intermediate_directory_symlink_is_refused(self) -> None:
        real = self.artifacts / "real-errors"
        (self.artifacts / "errors").rename(real)
        (self.artifacts / "errors").symlink_to(real, target_is_directory=True)
        self.assertEqual(self.run_scan(), 2)

    def test_recursive_archive_member_budget_is_shared(self) -> None:
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as output:
            for index in range(6):
                output.writestr(f"safe-{index}.txt", b"safe")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as output:
            output.writestr("one.zip", nested.getvalue())
            output.writestr("two.zip", nested.getvalue())
        with mock.patch.object(scanner, "MAX_ARCHIVE_MEMBERS", 10):
            with self.assertRaises(scanner.ScanRefused):
                scanner.scan_archive(
                    outer.getvalue(), "bomb.zip", (self.secret,)
                )

    def test_recursive_archive_expanded_byte_budget_is_shared(self) -> None:
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as output:
            output.writestr("one.txt", b"a" * 60)
            output.writestr("two.txt", b"b" * 60)
        with mock.patch.object(scanner, "MAX_ARCHIVE_EXPANDED_BYTES", 100):
            with self.assertRaises(scanner.ScanRefused):
                scanner.scan_archive(
                    outer.getvalue(), "expanded-bomb.zip", (self.secret,)
                )

    def test_file_namespace_swap_during_scan_is_refused(self) -> None:
        target = self.artifacts / "errors" / "captured-errors.json"
        root_fd = os.open(self.artifacts, scanner.DIRECTORY_FLAGS)
        original_read = scanner.os.read
        swapped = False

        def swapping_read(descriptor: int, size: int) -> bytes:
            nonlocal swapped
            body = original_read(descriptor, size)
            if body and not swapped:
                swapped = True
                target.rename(target.with_suffix(".old"))
                target.write_bytes(b"replacement")
            return body

        try:
            with mock.patch.object(scanner.os, "read", side_effect=swapping_read):
                with self.assertRaises(scanner.ScanRefused):
                    scanner.scan_file(root_fd, "errors/captured-errors.json", (self.secret,))
        finally:
            os.close(root_fd)

    def test_pinned_tree_fd_scans_original_after_runtime_path_swap(self) -> None:
        data = self.runtime / "data"
        (data / "escaped.log").write_bytes(self.secret)
        runtime_fd = os.open(self.runtime, scanner.DIRECTORY_FLAGS)
        root_fd = os.open(data, scanner.DIRECTORY_FLAGS)
        moved = self.root / "pinned-original"
        self.runtime.rename(moved)
        self.runtime.mkdir()
        (self.runtime / "data").mkdir()
        (self.runtime / "data" / "escaped.log").write_bytes(b"safe replacement")
        try:
            leaked, count = scanner.scan_tree(
                root_fd, (self.secret,), scanner.ArchiveBudget()
            )
            self.assertTrue(leaked)
            self.assertGreater(count, 0)
            with self.assertRaises(scanner.ScanRefused):
                scanner.verify_pinned_directory(self.runtime, runtime_fd)
        finally:
            os.close(root_fd)
            os.close(runtime_fd)

    def test_pattern_file_is_read_from_pinned_runtime_fd_after_path_swap(self) -> None:
        runtime_fd = os.open(self.runtime, scanner.DIRECTORY_FLAGS)
        moved = self.root / "runtime-original"
        self.runtime.rename(moved)
        self.runtime.mkdir()
        (self.runtime / "sensitive-patterns").write_bytes(b"attacker replacement\n")
        (self.runtime / "sensitive-patterns").chmod(0o600)
        try:
            patterns = scanner.private_pattern_file(
                runtime_fd, self.runtime, str(self.runtime / "sensitive-patterns")
            )
            self.assertIn(self.secret, patterns)
            self.assertNotIn(b"attacker replacement", patterns)
        finally:
            os.close(runtime_fd)

    def test_archive_budget_is_shared_across_top_level_files(self) -> None:
        first = self.artifacts / "errors" / "first.zip"
        second = self.artifacts / "errors" / "second.zip"
        for target in (first, second):
            with zipfile.ZipFile(target, "w") as output:
                for index in range(6):
                    output.writestr(f"safe-{index}.txt", b"safe")
        root_fd = os.open(self.artifacts, scanner.DIRECTORY_FLAGS)
        budget = scanner.ArchiveBudget()
        try:
            with mock.patch.object(scanner, "MAX_ARCHIVE_MEMBERS", 10):
                self.assertFalse(
                    scanner.scan_file(root_fd, "errors/first.zip", (self.secret,), budget)
                )
                with self.assertRaises(scanner.ScanRefused):
                    scanner.scan_file(
                        root_fd, "errors/second.zip", (self.secret,), budget
                    )
        finally:
            os.close(root_fd)

    def test_top_level_root_late_swap_with_new_secret_is_refused(self) -> None:
        artifact_fd = os.open(self.artifacts, scanner.DIRECTORY_FLAGS)
        original_scan = scanner.scan_tree

        def swap_after_scan(*args, **kwargs):
            result = original_scan(*args, **kwargs)
            moved = self.artifacts / "errors-original"
            (self.artifacts / "errors").rename(moved)
            (self.artifacts / "errors").mkdir()
            (self.artifacts / "errors" / "late-secret.log").write_bytes(self.secret)
            return result

        try:
            with mock.patch.object(scanner, "scan_tree", side_effect=swap_after_scan):
                with self.assertRaises(scanner.ScanRefused):
                    scanner.scan_top_entry(
                        artifact_fd,
                        "errors",
                        (self.secret,),
                        scanner.ArchiveBudget(),
                    )
        finally:
            os.close(artifact_fd)

    def test_previously_scanned_top_is_retained_until_global_revalidation(self) -> None:
        artifact_fd = os.open(self.artifacts, scanner.DIRECTORY_FLAGS)
        errors_fd = -1
        logs_fd = -1
        try:
            _, _, errors_fd, errors_baseline = scanner.pin_and_scan_top_entry(
                artifact_fd, "errors", (self.secret,), scanner.ArchiveBudget()
            )
            moved = self.artifacts / "errors-scanned"
            (self.artifacts / "errors").rename(moved)
            (self.artifacts / "errors").mkdir()
            (self.artifacts / "errors" / "late-secret.log").write_bytes(self.secret)
            _, _, logs_fd, _ = scanner.pin_and_scan_top_entry(
                artifact_fd, "logs", (self.secret,), scanner.ArchiveBudget()
            )
            with self.assertRaises(scanner.ScanRefused):
                scanner.revalidate_top_entry(
                    artifact_fd, "errors", errors_fd, errors_baseline
                )
        finally:
            if logs_fd >= 0:
                os.close(logs_fd)
            if errors_fd >= 0:
                os.close(errors_fd)
            os.close(artifact_fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
