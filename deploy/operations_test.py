#!/usr/bin/env python3

import hashlib
import importlib.util
import os
from pathlib import Path
import pty
import select
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OFFLINE_OPS = ROOT / "deploy" / "offline_ops.py"
OFFLINE_REVOKE = ROOT / "deploy" / "offline_revoke.py"
OPERATIONS_DOC = ROOT / "docs" / "operations.md"


def load_module(name: str, path: Path):
    if not path.is_file():
        raise AssertionError(f"missing operational helper: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load operational helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO fixture (value) VALUES ('valid')")
    connection.commit()
    connection.close()
    path.chmod(0o600)


class OfflineOpsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = (
            load_module("offline_ops", OFFLINE_OPS)
            if OFFLINE_OPS.is_file()
            else None
        )

    def setUp(self):
        self.assertIsNotNone(
            self.ops, f"missing operational helper: {OFFLINE_OPS}"
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.tempdir.cleanup()

    def assert_snapshot_rejected(self, source: Path) -> None:
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.ops.create_snapshot(
                source,
                self.root / "snapshot.sqlite3",
                self.root / "snapshot.sqlite3.sha256",
                self.uid,
                self.gid,
            )

    def test_snapshot_rejects_missing_source(self):
        self.assert_snapshot_rejected(self.root / "missing.sqlite3")

    def test_snapshot_rejects_symlink_source(self):
        real = self.root / "real.sqlite3"
        make_sqlite(real)
        link = self.root / "linked.sqlite3"
        link.symlink_to(real)
        self.assert_snapshot_rejected(link)

    def test_snapshot_rejects_empty_source(self):
        source = self.root / "empty.sqlite3"
        source.touch(mode=0o600)
        self.assert_snapshot_rejected(source)

    def test_snapshot_rejects_wrong_source_mode(self):
        source = self.root / "wide.sqlite3"
        make_sqlite(source)
        source.chmod(0o644)
        self.assert_snapshot_rejected(source)

    def test_snapshot_rejects_corrupt_source(self):
        source = self.root / "corrupt.sqlite3"
        source.write_bytes(b"not a sqlite database")
        source.chmod(0o600)
        self.assert_snapshot_rejected(source)

    def test_integrity_requires_exact_ok_output(self):
        result = subprocess.CompletedProcess(
            ["sqlite3"], 0, stdout=b"ok\nextra\n", stderr=b""
        )
        with mock.patch.object(self.ops.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError):
                self.ops.verify_integrity(self.root / "fixture.sqlite3")

    def test_snapshot_creates_verified_private_file_and_manifest(self):
        source = self.root / "source.sqlite3"
        snapshot = self.root / "snapshot.sqlite3"
        manifest = self.root / "snapshot.sqlite3.sha256"
        make_sqlite(source)

        digest = self.ops.create_snapshot(
            source, snapshot, manifest, self.uid, self.gid
        )

        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
        self.assertGreater(snapshot.stat().st_size, 0)
        self.assertEqual(
            manifest.read_text(encoding="ascii"),
            f"{digest}  {snapshot.name}\n",
        )
        self.assertEqual(digest, hashlib.sha256(snapshot.read_bytes()).hexdigest())
        self.ops.verify_integrity(snapshot)

    def create_git_checkout(self) -> tuple[Path, str]:
        repository = self.root / "repository"
        checkout = self.root / "checkout"
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.email", "fixture@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "Fixture"],
            check=True,
        )
        (repository / "release.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", repository, "add", "release.txt"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "fixture"], check=True
        )
        subprocess.run(
            ["git", "-C", repository, "worktree", "add", "--detach", checkout],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        revision = subprocess.check_output(
            ["git", "-C", checkout, "rev-parse", "HEAD"], text=True
        ).strip()
        return checkout, revision

    def make_restore_fixture(self) -> tuple[Path, str, Path, str]:
        checkout, revision = self.create_git_checkout()
        snapshot = self.root / "restore.sqlite3"
        make_sqlite(snapshot)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        return checkout, revision, snapshot, digest

    def test_restore_preflight_rejects_wrong_revision(self):
        checkout, _, snapshot, digest = self.make_restore_fixture()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.ops.restore_preflight(
                checkout, "v1.0.0", "0" * 40, snapshot, digest, self.uid, self.gid
            )

    def test_restore_preflight_rejects_missing_snapshot(self):
        checkout, revision = self.create_git_checkout()
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    self.root / "missing.sqlite3",
                    "0" * 64,
                    self.uid,
                    self.gid,
                )

    def test_restore_preflight_rejects_empty_snapshot(self):
        checkout, revision = self.create_git_checkout()
        snapshot = self.root / "empty-restore.sqlite3"
        snapshot.touch(mode=0o600)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    snapshot,
                    digest,
                    self.uid,
                    self.gid,
                )

    def test_restore_preflight_rejects_wrong_checksum(self):
        checkout, revision, snapshot, _ = self.make_restore_fixture()
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    snapshot,
                    "0" * 64,
                    self.uid,
                    self.gid,
                )

    def test_restore_preflight_rejects_corrupt_snapshot(self):
        checkout, revision = self.create_git_checkout()
        snapshot = self.root / "corrupt.sqlite3"
        snapshot.write_bytes(b"not a sqlite database")
        snapshot.chmod(0o600)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    snapshot,
                    digest,
                    self.uid,
                    self.gid,
                )

    def test_restore_preflight_accepts_exact_revision_checksum_and_database(self):
        checkout, revision, snapshot, digest = self.make_restore_fixture()
        with mock.patch.object(self.ops, "verify_release_tag") as verify_tag:
            self.ops.restore_preflight(
                checkout,
                "v1.0.0",
                revision,
                snapshot,
                digest,
                self.uid,
                self.gid,
            )
        verify_tag.assert_called_once_with(checkout, "v1.0.0", revision)

    def test_restore_preflight_rejects_symlink_snapshot(self):
        checkout, revision, snapshot, digest = self.make_restore_fixture()
        link = self.root / "linked-restore.sqlite3"
        link.symlink_to(snapshot)
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    link,
                    digest,
                    self.uid,
                    self.gid,
                )

    def test_restore_preflight_rejects_untracked_build_context(self):
        checkout, revision, snapshot, digest = self.make_restore_fixture()
        (checkout / "untracked-build-input").write_text(
            "unexpected\n", encoding="utf-8"
        )
        with mock.patch.object(self.ops, "verify_release_tag"):
            with self.assertRaises(RuntimeError):
                self.ops.restore_preflight(
                    checkout,
                    "v1.0.0",
                    revision,
                    snapshot,
                    digest,
                    self.uid,
                    self.gid,
                )

    def test_release_tag_verification_failure_is_rejected(self):
        checkout, revision, _, _ = self.make_restore_fixture()
        failed = subprocess.CompletedProcess(
            ["git", "verify-tag"], 1, stdout=b"", stderr=b"bad signature"
        )
        with mock.patch.object(self.ops.subprocess, "run", return_value=failed):
            with self.assertRaises(RuntimeError):
                self.ops.verify_release_tag(checkout, "v1.0.0", revision)


class OfflineRevokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.revoke = (
            load_module("offline_revoke", OFFLINE_REVOKE)
            if OFFLINE_REVOKE.is_file()
            else None
        )

    def setUp(self):
        self.assertIsNotNone(
            self.revoke, f"missing operational helper: {OFFLINE_REVOKE}"
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name).resolve() / "opswarden.db"
        self.connection = sqlite3.connect(self.db_path, isolation_level=None)
        self.connection.executescript(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                normalized_email TEXT NOT NULL UNIQUE
            );
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE agents (
                id TEXT PRIMARY KEY
            );
            CREATE TABLE agent_tokens (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                revoked_at TEXT
            );
            INSERT INTO users (id, normalized_email)
            VALUES ('user-1', 'owner@example.com');
            """
        )

    def tearDown(self):
        self.connection.close()
        self.tempdir.cleanup()

    def test_orchestration_reads_tty_before_drop_and_opens_db_after_drop(self):
        events = []
        kind = bytearray(b"user")
        identifier = bytearray(b"owner@example.com")

        def read_selection():
            events.append("tty")
            return kind, identifier

        def drop_privileges(uid, gid):
            events.append(("drop", uid, gid))

        def open_database(path, uid, gid):
            events.append(("open", path, uid, gid))
            return self.connection

        count = self.revoke.orchestrate(
            self.db_path,
            10001,
            10001,
            lambda: events.append("root"),
            read_selection,
            drop_privileges,
            open_database,
            lambda connection, selected_kind, selected_identifier: 1,
        )

        self.assertEqual(count, 1)
        self.assertEqual(
            events,
            [
                "root",
                "tty",
                ("drop", 10001, 10001),
                ("open", self.db_path, 10001, 10001),
            ],
        )
        self.assertEqual(kind, bytearray(len(kind)))
        self.assertEqual(identifier, bytearray(len(identifier)))

    def test_hidden_tty_input_is_not_echoed(self):
        master_fd, slave_fd = pty.openpty()
        tty_path = os.ttyname(slave_fd)
        supplied = b"user\nowner@example.com\n"

        def write_after_noecho_is_installed():
            time.sleep(0.1)
            os.write(master_fd, supplied)

        writer = threading.Thread(target=write_after_noecho_is_installed)
        writer.start()
        kind, identifier = self.revoke.read_hidden_selection(
            tty_path, expected_owner_uid=os.getuid()
        )
        writer.join(timeout=2)

        captured = bytearray()
        while select.select([master_fd], [], [], 0.05)[0]:
            captured.extend(os.read(master_fd, 4096))
        os.close(master_fd)
        os.close(slave_fd)

        self.assertEqual(kind, bytearray(b"user"))
        self.assertEqual(identifier, bytearray(b"owner@example.com"))
        self.assertNotIn(b"owner@example.com", captured)

    def test_privilege_drop_verifies_all_real_and_effective_ids(self):
        with mock.patch.object(
            self.revoke.os, "setgroups"
        ) as setgroups, mock.patch.object(
            self.revoke.os, "setgid"
        ) as setgid, mock.patch.object(
            self.revoke.os, "setuid"
        ) as setuid, mock.patch.object(
            self.revoke.os, "getuid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "geteuid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "getgid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "getegid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "getgroups", return_value=[]
        ):
            self.revoke.drop_privileges(10001, 10001)

        setgroups.assert_called_once_with([])
        setgid.assert_called_once_with(10001)
        setuid.assert_called_once_with(10001)

    def test_privilege_drop_rejects_incomplete_drop(self):
        with mock.patch.object(
            self.revoke.os, "setgroups"
        ), mock.patch.object(
            self.revoke.os, "setgid"
        ), mock.patch.object(
            self.revoke.os, "setuid"
        ), mock.patch.object(
            self.revoke.os, "getuid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "geteuid", return_value=0
        ), mock.patch.object(
            self.revoke.os, "getgid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "getegid", return_value=10001
        ), mock.patch.object(
            self.revoke.os, "getgroups", return_value=[]
        ):
            with self.assertRaises(PermissionError):
                self.revoke.drop_privileges(10001, 10001)

    def test_database_open_rejects_missing_empty_corrupt_and_symlink(self):
        missing = self.db_path.parent / "missing.db"
        empty = self.db_path.parent / "empty.db"
        empty.touch(mode=0o600)
        corrupt = self.db_path.parent / "corrupt.db"
        corrupt.write_bytes(b"not a sqlite database")
        corrupt.chmod(0o600)
        link = self.db_path.parent / "linked.db"
        link.symlink_to(self.db_path)

        for path in (missing, empty, corrupt, link):
            with self.subTest(path=path.name):
                with self.assertRaises(
                    (OSError, RuntimeError, ValueError, sqlite3.Error)
                ):
                    self.revoke.open_database(
                        path, os.getuid(), os.getgid()
                    )

    def test_zero_active_rows_rolls_back(self):
        with self.assertRaises(RuntimeError):
            self.revoke.revoke_active(
                self.connection,
                bytearray(b"user"),
                bytearray(b"owner@example.com"),
            )

        self.assertFalse(self.connection.in_transaction)
        count = self.connection.execute(
            "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_exact_active_rows_commit(self):
        self.connection.executescript(
            """
            INSERT INTO sessions (id, user_id, revoked_at)
            VALUES ('active', 'user-1', NULL);
            INSERT INTO sessions (id, user_id, revoked_at)
            VALUES ('already-revoked', 'user-1', '2026-01-01T00:00:00Z');
            """
        )

        count = self.revoke.revoke_active(
            self.connection,
            bytearray(b"user"),
            bytearray(b"Owner@Example.COM"),
        )

        self.assertEqual(count, 1)
        rows = self.connection.execute(
            "SELECT id, revoked_at FROM sessions ORDER BY id"
        ).fetchall()
        self.assertIsNotNone(rows[0][1])
        self.assertEqual(rows[1][1], "2026-01-01T00:00:00Z")
        self.assertFalse(self.connection.in_transaction)

    def test_commit_failure_rolls_back(self):
        self.connection.execute(
            """
            INSERT INTO sessions (id, user_id, revoked_at)
            VALUES ('active', 'user-1', NULL)
            """
        )

        class FailingCommit:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, *args, **kwargs):
                return self.connection.execute(*args, **kwargs)

            def commit(self):
                raise sqlite3.OperationalError("fixture commit failure")

            def rollback(self):
                self.connection.rollback()

        with self.assertRaises(sqlite3.OperationalError):
            self.revoke.revoke_active(
                FailingCommit(self.connection),
                bytearray(b"user"),
                bytearray(b"owner@example.com"),
            )

        self.assertFalse(self.connection.in_transaction)
        revoked = self.connection.execute(
            "SELECT revoked_at FROM sessions WHERE id = 'active'"
        ).fetchone()[0]
        self.assertIsNone(revoked)


class OperationsDocumentationTest(unittest.TestCase):
    def test_runbook_uses_hardened_helpers_before_compose_restore(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        restore = text[text.index("## 8. 每季度隔离恢复演练") : text.index("## 9.")]
        self.assertIn("offline_ops.py restore-preflight", restore)
        preflight = restore.index("offline_ops.py restore-preflight")
        compose = restore.index("docker compose")
        self.assertLess(preflight, compose)
        self.assertIn("git worktree add --detach", restore)
        self.assertIn('git verify-tag "refs/tags/$release_ref"', restore)
        self.assertIn('rev-parse HEAD)" != "$expected_revision"', restore)

    def test_runbook_uses_root_first_offline_revocation_helper(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        revoke = text[text.index("## 9. 紧急吊销") : text.index("## 10.")]
        self.assertIn("sudo -- python3 deploy/offline_revoke.py", revoke)
        self.assertNotIn("sudo -u '#10001' python3 -", revoke)


if __name__ == "__main__":
    unittest.main(verbosity=2)
