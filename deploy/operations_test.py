#!/usr/bin/env python3

import hashlib
import base64
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
RESTORE_OVERRIDE = ROOT / "deploy" / "restore.override.yaml"
USER_ID = base64.urlsafe_b64encode(bytes(16)).rstrip(b"=").decode("ascii")
TOKEN_ID = "tok_" + "a" * 32


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
        self.fixture_count = 0

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

    def make_release(self) -> tuple[Path, Path, str, int]:
        self.fixture_count += 1
        release = self.root / f"release-{self.fixture_count}"
        deploy = release / "deploy"
        deploy.mkdir(parents=True)
        files = {
            ".gitattributes": b"*.txt filter=evil diff=evil\n",
            "deploy/Dockerfile": b"FROM scratch\n",
            "release.txt": b"fixture\n",
        }
        for relative, content in files.items():
            path = release / relative
            path.write_bytes(content)
            path.chmod(0o444)
        deploy.chmod(0o555)
        release.chmod(0o555)
        revision = "a" * 40
        tree = "b" * 40
        epoch = 1700000000
        lines = [
            self.ops.MANIFEST_HEADER,
            "tag v1.0.0",
            f"revision {revision}",
            f"tree {tree}",
            f"epoch {epoch}",
        ]
        for relative, content in sorted(files.items()):
            lines.append(
                f"100644 {len(content)} {hashlib.sha256(content).hexdigest()} {relative}"
            )
        manifest = self.root / f"release-{self.fixture_count}.manifest"
        manifest.write_text("\n".join(lines) + "\n", encoding="ascii")
        manifest.chmod(0o444)
        return release, manifest, revision, epoch

    def make_restore_fixture(self) -> tuple[Path, Path, str, Path, str]:
        release, manifest, revision, _ = self.make_release()
        snapshot = self.root / f"restore-{self.fixture_count}.sqlite3"
        make_sqlite(snapshot)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        return release, manifest, revision, snapshot, digest

    def restore(self, release, manifest, revision, snapshot, digest):
        return self.ops.restore_preflight(
            release,
            manifest,
            "v1.0.0",
            revision,
            snapshot,
            digest,
            self.uid,
            self.gid,
            release_uid=self.uid,
            release_gid=self.gid,
        )

    def test_restore_preflight_rejects_wrong_revision(self):
        release, manifest, _, snapshot, digest = self.make_restore_fixture()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(release, manifest, "0" * 40, snapshot, digest)

    def test_restore_preflight_rejects_missing_snapshot(self):
        release, manifest, revision, _ = self.make_release()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(
                release,
                manifest,
                revision,
                self.root / "missing.sqlite3",
                "0" * 64,
            )

    def test_restore_preflight_rejects_empty_snapshot(self):
        release, manifest, revision, _ = self.make_release()
        snapshot = self.root / "empty-restore.sqlite3"
        snapshot.touch(mode=0o600)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(release, manifest, revision, snapshot, digest)

    def test_restore_preflight_rejects_wrong_checksum(self):
        release, manifest, revision, snapshot, _ = self.make_restore_fixture()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(release, manifest, revision, snapshot, "0" * 64)

    def test_restore_preflight_rejects_corrupt_snapshot(self):
        release, manifest, revision, _ = self.make_release()
        snapshot = self.root / "corrupt.sqlite3"
        snapshot.write_bytes(b"not a sqlite database")
        snapshot.chmod(0o600)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(release, manifest, revision, snapshot, digest)

    def test_restore_preflight_accepts_exact_revision_checksum_and_database(self):
        release, manifest, revision, snapshot, digest = self.make_restore_fixture()
        self.restore(release, manifest, revision, snapshot, digest)

    def test_restore_preflight_rejects_symlink_snapshot(self):
        release, manifest, revision, snapshot, digest = self.make_restore_fixture()
        link = self.root / "linked-restore.sqlite3"
        link.symlink_to(snapshot)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self.restore(release, manifest, revision, link, digest)

    def test_restore_preflight_rejects_untracked_build_context(self):
        release, manifest, revision, snapshot, digest = self.make_restore_fixture()
        release.chmod(0o755)
        (release / "untracked-build-input").write_text(
            "unexpected\n", encoding="utf-8"
        )
        with self.assertRaises((PermissionError, RuntimeError)):
            self.restore(release, manifest, revision, snapshot, digest)

    def test_restore_rejects_modified_mode_digest_symlink_and_special_paths(self):
        for mutation in ("mode", "digest", "symlink"):
            with self.subTest(mutation=mutation):
                release, manifest, revision, snapshot, digest = self.make_restore_fixture()
                target = release / "release.txt"
                release.chmod(0o755)
                if mutation == "mode":
                    target.chmod(0o644)
                elif mutation == "digest":
                    target.chmod(0o644)
                    target.write_bytes(b"malicious\n")
                    target.chmod(0o444)
                else:
                    target.unlink()
                    target.symlink_to("/etc/passwd")
                release.chmod(0o555)
                with self.assertRaises((OSError, RuntimeError, ValueError)):
                    self.restore(release, manifest, revision, snapshot, digest)

    def test_root_preflight_never_executes_malicious_git_configuration(self):
        release, manifest, revision, snapshot, digest = self.make_restore_fixture()
        attacker = self.root / "attacker-repo"
        marker_names = ("clean", "smudge", "diff", "fsmonitor", "hook", "gpg", "env")
        subprocess.run(["git", "init", "-q", attacker], check=True)
        for name in marker_names:
            command = self.root / f"{name}.sh"
            command.write_text(
                f"#!/bin/sh\n: > '{self.root / (name + '.marker')}'\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
        attributes = release / ".gitattributes"
        self.assertIn("filter=evil", attributes.read_text(encoding="utf-8"))
        subprocess.run(
            ["git", "-C", attacker, "config", "filter.evil.clean", str(self.root / "clean.sh")],
            check=True,
        )
        subprocess.run(
            ["git", "-C", attacker, "config", "filter.evil.smudge", str(self.root / "smudge.sh")],
            check=True,
        )
        subprocess.run(
            ["git", "-C", attacker, "config", "diff.external", str(self.root / "diff.sh")],
            check=True,
        )
        subprocess.run(
            ["git", "-C", attacker, "config", "core.fsmonitor", str(self.root / "fsmonitor.sh")],
            check=True,
        )
        subprocess.run(
            ["git", "-C", attacker, "config", "core.hooksPath", str(self.root)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", attacker, "config", "gpg.program", str(self.root / "gpg.sh")],
            check=True,
        )
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": str(attacker / ".git"),
                "GIT_WORK_TREE": str(release),
                "GIT_EXTERNAL_DIFF": str(self.root / "env.sh"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": str(self.root / "fsmonitor.sh"),
            },
            clear=False,
        ):
            self.restore(release, manifest, revision, snapshot, digest)
        for name in marker_names:
            self.assertFalse((self.root / f"{name}.marker").exists(), name)
        source = OFFLINE_OPS.read_text(encoding="utf-8")
        self.assertNotIn('"/usr/bin/git"', source)
        self.assertNotRegex(source, r'git_command|verify_release_tag|verify_pristine_worktree')

    def test_hermetic_plumbing_ignores_git_injection_and_exposes_replace_ref(self):
        repository = self.root / "hostile-repository"
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.email", "fixture@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "Fixture"],
            check=True,
        )
        payload = repository / "payload.txt"
        payload.write_text("genuine\n", encoding="utf-8")
        (repository / ".gitattributes").write_text(
            "*.txt filter=evil diff=evil\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", repository, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-qm", "genuine"], check=True
        )
        genuine = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD"], text=True
        ).strip()
        genuine_tree = subprocess.check_output(
            ["git", "--no-replace-objects", "-C", repository, "rev-parse", "HEAD^{tree}"],
            text=True,
        ).strip()
        payload.write_text("malicious\n", encoding="utf-8")
        subprocess.run(["git", "-C", repository, "commit", "-qam", "malicious"], check=True)
        malicious = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(["git", "-C", repository, "replace", genuine, malicious], check=True)

        markers = {}
        for name in ("clean", "smudge", "diff", "fsmonitor", "hook", "gpg", "env"):
            marker = self.root / f"hermetic-{name}.marker"
            command = self.root / f"hermetic-{name}.sh"
            command.write_text(f"#!/bin/sh\n: > '{marker}'\n", encoding="utf-8")
            command.chmod(0o755)
            markers[name] = marker
        for key, value in (
            ("filter.evil.clean", self.root / "hermetic-clean.sh"),
            ("filter.evil.smudge", self.root / "hermetic-smudge.sh"),
            ("diff.external", self.root / "hermetic-diff.sh"),
            ("core.fsmonitor", self.root / "hermetic-fsmonitor.sh"),
            ("core.hooksPath", self.root),
            ("gpg.program", self.root / "hermetic-gpg.sh"),
        ):
            subprocess.run(
                ["git", "-C", repository, "config", key, str(value)], check=True
            )

        command_prefix = [
            "/usr/bin/git",
            "--no-replace-objects",
            "-c",
            f"safe.directory={repository}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "fsck.skipList=/dev/null",
            "-c",
            "receive.fsck.skipList=/dev/null",
            "-c",
            "fetch.fsck.skipList=/dev/null",
            "-c",
            "gpg.format=openpgp",
            "-c",
            "gpg.program=/usr/bin/gpg",
            "-c",
            "gpg.minTrustLevel=fully",
            "-C",
            str(repository),
        ]
        environment = {
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GNUPGHOME": str(self.root / "fixed-keyring"),
        }
        injected = {
            "GIT_DIR": str(self.root / "wrong.git"),
            "GIT_WORK_TREE": str(self.root / "wrong-tree"),
            "GIT_OBJECT_DIRECTORY": str(self.root / "wrong-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / "wrong-alternates"),
            "GIT_EXTERNAL_DIFF": str(self.root / "hermetic-env.sh"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": str(self.root / "hermetic-fsmonitor.sh"),
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            resolved_tree = subprocess.check_output(
                command_prefix + ["rev-parse", f"{genuine}^{{tree}}"],
                env=environment,
                text=True,
            ).strip()
            subprocess.check_output(
                command_prefix + ["ls-tree", "-r", "-z", genuine], env=environment
            )
            blob = subprocess.check_output(
                command_prefix + ["rev-parse", f"{genuine}:payload.txt"],
                env=environment,
                text=True,
            ).strip()
            self.assertEqual(
                subprocess.check_output(
                    command_prefix + ["cat-file", "blob", blob], env=environment
                ),
                b"genuine\n",
            )
            replace_refs = subprocess.check_output(
                command_prefix
                + ["for-each-ref", "--format=%(refname)", "refs/replace/"],
                env=environment,
                text=True,
            )
            subprocess.run(
                command_prefix + ["fsck", "--strict", "--no-reflogs", genuine],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        self.assertEqual(resolved_tree, genuine_tree)
        self.assertIn("refs/replace/", replace_refs)
        self.assertEqual(
            subprocess.check_output(
                command_prefix + ["config", "--get", "gpg.program"],
                env=environment,
                text=True,
            ).strip(),
            "/usr/bin/gpg",
        )
        for name, marker in markers.items():
            self.assertFalse(marker.exists(), name)

    def test_atomic_blob_install_uses_open_stream_not_swapped_path(self):
        source = self.root / "helper.py"
        genuine = b"#!/usr/bin/python3\nprint('genuine')\n"
        malicious = b"#!/usr/bin/python3\nprint('malicious')\n"
        source.write_bytes(genuine)
        descriptor = os.open(source, os.O_RDONLY)
        replacement = self.root / "replacement.py"
        replacement.write_bytes(malicious)
        os.replace(replacement, source)
        destination_parent = self.root / "trusted"
        destination_parent.mkdir(mode=0o755)
        destination = destination_parent / "offline_ops.py"
        try:
            self.ops.atomic_install_blob(
                descriptor,
                destination,
                hashlib.sha256(genuine).hexdigest(),
                len(genuine),
                self.uid,
                self.gid,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(destination.read_bytes(), genuine)
        self.assertNotEqual(destination.read_bytes(), source.read_bytes())

    def test_restore_env_rejects_template_defaults_duplicates_and_symlink(self):
        env_path = self.root / "restore.env"
        env_path.write_text(
            (ROOT / "deploy" / ".env.example").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        env_path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.ops.verify_restore_environment(
                env_path, self.uid, self.gid, "v1.0.0", "a" * 40, 0
            )
        env_path.write_text(
            "OPSWARDEN_HOSTNAME=localhost\nOPSWARDEN_HOSTNAME=localhost\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.ops.parse_environment_file(env_path, self.uid, self.gid)
        real = self.root / "real.env"
        real.write_text("OPSWARDEN_HOSTNAME=localhost\n", encoding="utf-8")
        real.chmod(0o600)
        env_path.unlink()
        env_path.symlink_to(real)
        with self.assertRaises((OSError, ValueError)):
            self.ops.parse_environment_file(env_path, self.uid, self.gid)

    def valid_restore_env(self, revision: str, epoch: int) -> str:
        return "\n".join(
            (
                "OPSWARDEN_HOSTNAME=localhost",
                "OPSWARDEN_TLS_EMAIL=ops@example.com",
                "OPSWARDEN_VERSION=1.0.0",
                f"OPSWARDEN_REVISION={revision}",
                f"SOURCE_DATE_EPOCH={epoch}",
                "OPSWARDEN_STATE_PATH=/srv/opswarden-restore/state",
                (
                    "OPSWARDEN_MASTER_KEY_PATH="
                    "/srv/opswarden-restore/secrets/master.key"
                ),
                "CADDY_DATA_PATH=/srv/opswarden-restore/caddy/data",
                "CADDY_CONFIG_PATH=/srv/opswarden-restore/caddy/config",
                "OPSWARDEN_BACKEND_SUBNET=172.31.251.0/29",
                "OPSWARDEN_APP_IP=172.31.251.2",
                "OPSWARDEN_CADDY_IP=172.31.251.3",
                "OPSWARDEN_INTERNAL_CIDRS=",
                "OPSWARDEN_RESTORE_HOST_PORT=127.0.0.1:8443:443/tcp",
                "",
            )
        )

    def test_restore_env_accepts_only_exact_isolated_policy(self):
        revision = "a" * 40
        env_path = self.root / "valid.env"
        env_path.write_text(
            self.valid_restore_env(revision, 1234), encoding="ascii"
        )
        env_path.chmod(0o600)
        self.ops.verify_restore_environment(
            env_path, self.uid, self.gid, "v1.0.0", revision, 1234
        )

        mutations = {
            "production state": (
                "/srv/opswarden-restore/state",
                "/srv/opswarden/state",
            ),
            "production key": (
                "/srv/opswarden-restore/secrets/master.key",
                "/srv/opswarden/secrets/master.key",
            ),
            "revision mismatch": (revision, "b" * 40),
            "public port": (
                "127.0.0.1:8443:443/tcp",
                "0.0.0.0:8443:443/tcp",
            ),
        }
        original = self.valid_restore_env(revision, 1234)
        for name, (old, new) in mutations.items():
            with self.subTest(name=name):
                env_path.write_text(original.replace(old, new), encoding="ascii")
                with self.assertRaises(ValueError):
                    self.ops.verify_restore_environment(
                        env_path,
                        self.uid,
                        self.gid,
                        "v1.0.0",
                        revision,
                        1234,
                    )
        env_path.write_text(original, encoding="ascii")
        env_path.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.ops.verify_restore_environment(
                env_path, self.uid, self.gid, "v1.0.0", revision, 1234
            )
        env_path.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.ops.verify_restore_environment(
                env_path, self.uid + 1, self.gid, "v1.0.0", revision, 1234
            )

    def test_trusted_helper_rejects_writable_or_symlink_file(self):
        helper = self.root / "offline_ops.py"
        helper.write_text("# trusted fixture\n", encoding="ascii")
        helper.chmod(0o755)
        self.ops.verify_trusted_helper(
            helper, helper, expected_uid=self.uid, expected_gid=self.gid
        )
        helper.chmod(0o775)
        with self.assertRaises(PermissionError):
            self.ops.verify_trusted_helper(
                helper, helper, expected_uid=self.uid, expected_gid=self.gid
            )
        helper.chmod(0o755)
        link = self.root / "worktree-offline_ops.py"
        link.symlink_to(helper)
        with self.assertRaises(PermissionError):
            self.ops.verify_trusted_helper(
                link, link, expected_uid=self.uid, expected_gid=self.gid
            )


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
            VALUES ('AAAAAAAAAAAAAAAAAAAAAA', 'owner@example.com');
            """
        )

    def tearDown(self):
        self.connection.close()
        self.tempdir.cleanup()

    def test_orchestration_reads_tty_before_drop_and_opens_db_after_drop(self):
        events = []
        kind = bytearray(b"user")
        identifier = bytearray(USER_ID.encode("ascii"))

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

    def test_revocation_helper_rejects_writable_worktree_copy(self):
        helper = Path(self.tempdir.name).resolve() / "offline_revoke.py"
        helper.write_text("# fixture\n", encoding="ascii")
        helper.chmod(0o775)
        with self.assertRaises(PermissionError):
            self.revoke.verify_trusted_helper(
                helper,
                expected_path=helper,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )

    def test_hidden_tty_input_is_not_echoed(self):
        master_fd, slave_fd = pty.openpty()
        tty_path = os.ttyname(slave_fd)
        supplied = b"user\n" + USER_ID.encode("ascii") + b"\n"

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
        self.assertEqual(identifier, bytearray(USER_ID.encode("ascii")))
        self.assertNotIn(USER_ID.encode("ascii"), captured)

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
                bytearray(USER_ID.encode("ascii")),
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
            VALUES ('active', 'AAAAAAAAAAAAAAAAAAAAAA', NULL);
            INSERT INTO sessions (id, user_id, revoked_at)
            VALUES ('already-revoked', 'AAAAAAAAAAAAAAAAAAAAAA', '2026-01-01T00:00:00Z');
            """
        )

        count = self.revoke.revoke_active(
            self.connection,
            bytearray(b"user"),
            bytearray(USER_ID.encode("ascii")),
        )

        self.assertEqual(count, 1)
        rows = self.connection.execute(
            "SELECT id, revoked_at FROM sessions ORDER BY id"
        ).fetchall()
        self.assertIsNotNone(rows[0][1])
        self.assertEqual(rows[1][1], "2026-01-01T00:00:00Z")
        self.assertFalse(self.connection.in_transaction)

    def test_exact_token_id_commit_and_zero_row_rollback(self):
        self.connection.executescript(
            f"""
            INSERT INTO agents (id) VALUES ('agt_fixture');
            INSERT INTO agent_tokens (id, agent_id, revoked_at)
            VALUES ('{TOKEN_ID}', 'agt_fixture', NULL);
            """
        )
        count = self.revoke.revoke_active(
            self.connection,
            bytearray(b"token"),
            bytearray(TOKEN_ID.encode("ascii")),
        )
        self.assertEqual(count, 1)
        self.assertIsNotNone(
            self.connection.execute(
                "SELECT revoked_at FROM agent_tokens WHERE id = ?", (TOKEN_ID,)
            ).fetchone()[0]
        )
        with self.assertRaises(RuntimeError):
            self.revoke.revoke_active(
                self.connection,
                bytearray(b"token"),
                bytearray(TOKEN_ID.encode("ascii")),
            )
        self.assertFalse(self.connection.in_transaction)

    def test_commit_failure_rolls_back(self):
        self.connection.execute(
            """
            INSERT INTO sessions (id, user_id, revoked_at)
            VALUES ('active', 'AAAAAAAAAAAAAAAAAAAAAA', NULL)
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
                bytearray(USER_ID.encode("ascii")),
            )

        self.assertFalse(self.connection.in_transaction)
        revoked = self.connection.execute(
            "SELECT revoked_at FROM sessions WHERE id = 'active'"
        ).fetchone()[0]
        self.assertIsNone(revoked)

    def test_rejects_email_unicode_and_agent_id_selectors(self):
        for kind, identifier in (
            (b"user", b"owner@example.com"),
            (b"user", "用户".encode("utf-8")),
            (b"token", b"agt_" + b"a" * 32),
        ):
            with self.subTest(kind=kind, identifier=identifier):
                with self.assertRaises(ValueError):
                    self.revoke.revoke_active(
                        self.connection, bytearray(kind), bytearray(identifier)
                    )


class OperationsDocumentationTest(unittest.TestCase):
    def test_runbook_uses_hardened_helpers_before_compose_restore(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        restore = text[text.index("## 8. 每季度隔离恢复演练") : text.index("## 9.")]
        self.assertIn("offline_ops.py restore-preflight", restore)
        preflight = restore.index("offline_ops.py restore-preflight")
        compose = restore.index("docker compose")
        self.assertLess(preflight, compose)
        self.assertIn("offline_ops.py seal-release", restore)
        self.assertIn("safe_git ls-tree -r -z --full-tree", restore)
        self.assertNotIn("safe_git worktree add", restore)
        self.assertNotIn("safe_git checkout", restore)
        self.assertIn('safe_git verify-tag "refs/tags/$release_ref"', restore)
        self.assertIn('rev-parse "${expected_revision}^{tree}"', restore)

    def test_runbook_uses_root_first_offline_revocation_helper(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        revoke = text[text.index("## 9. 紧急吊销") : text.index("## 10.")]
        self.assertIn(
            "sudo -- python3 /usr/local/libexec/opswarden/offline_revoke.py",
            revoke,
        )
        self.assertNotIn("sudo -u '#10001' python3 -", revoke)

    def test_privileged_helpers_use_only_root_owned_trust_anchor(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        self.assertIn("/usr/local/libexec/opswarden/offline_ops.py", text)
        self.assertIn("/usr/local/libexec/opswarden/offline_revoke.py", text)
        self.assertNotIn(
            "sudo -- python3 /srv/opswarden-restore/source/deploy/offline_ops.py",
            text,
        )
        self.assertNotIn("sudo -- python3 deploy/offline_revoke.py", text)

    def test_restore_uses_hermetic_git_and_private_operator_staging(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        restore = text[text.index("## 8. 每季度隔离恢复演练") : text.index("## 9.")]
        for required in (
            "env -i",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GNUPGHOME=/etc/opswarden/release-gnupg",
            "--no-replace-objects",
            "safe.directory=/opt/opswarden",
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "core.attributesFile=/dev/null",
            "diff.external=",
            "fsck.skipList=/dev/null",
            "receive.fsck.skipList=/dev/null",
            "fetch.fsck.skipList=/dev/null",
            "gpg.program=/usr/bin/gpg",
            "gpg.minTrustLevel=fully",
        ):
            self.assertIn(required, restore)
        self.assertIn("refs/replace/", restore)
        self.assertIn("-m 0700", restore)
        self.assertIn("RESTORE_OPERATOR_UID", restore)
        self.assertIn(
            "/usr/local/libexec/opswarden/offline_ops.py restore-preflight",
            restore,
        )
        self.assertIn("/srv/opswarden-restore/restore.env", restore)
        self.assertNotIn("/srv/opswarden-restore/override.yaml", restore)
        self.assertNotIn("/srv/opswarden-restore-worktree", restore)

    def test_trust_anchor_install_streams_exact_blob_atomically(self):
        text = OPERATIONS_DOC.read_text(encoding="utf-8")
        anchor = text[text.index("### 固定的 root-owned 运维辅助程序") : text.index("## 2.")]
        self.assertIn("safe_git cat-file blob \"$object_id\" |", anchor)
        self.assertIn("tempfile.mkstemp", anchor)
        self.assertIn("os.fsync", anchor)
        self.assertIn("os.fchown", anchor)
        self.assertIn("os.fchmod", anchor)
        self.assertIn("os.replace", anchor)
        self.assertNotIn("cmp -s", anchor)
        self.assertNotIn("sudo install -o root -g root -m 0755 --", anchor)

    def test_root_helper_has_no_git_execution_or_worktree_inspection(self):
        source = OFFLINE_OPS.read_text(encoding="utf-8")
        for forbidden in (
            "/usr/bin/git",
            "git_command",
            "verify_release_tag",
            "verify_pristine_worktree",
            '"status"',
            '"diff"',
            '"checkout"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("verify_release_filesystem", source)
        self.assertIn("seal_release", source)

    def test_signed_restore_override_uses_only_env_loopback_port(self):
        override = RESTORE_OVERRIDE.read_text(encoding="utf-8")
        self.assertIn("${OPSWARDEN_RESTORE_HOST_PORT:", override)
        self.assertIn(
            "/srv/opswarden-restore/release/deploy/RestoreCaddyfile",
            override,
        )
        self.assertNotIn("0.0.0.0:", override)


if __name__ == "__main__":
    unittest.main(verbosity=2)
