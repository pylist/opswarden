#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ReleaseGateSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="opswarden-gate-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_git_repo(self) -> tuple[Path, str]:
        repository = self.root / "repository"
        repository.mkdir()
        subprocess.run(["/usr/bin/git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(
            ["/usr/bin/git", "config", "user.email", "test@example.invalid"],
            cwd=repository,
            check=True,
        )
        subprocess.run(
            ["/usr/bin/git", "config", "user.name", "Gate Test"],
            cwd=repository,
            check=True,
        )
        (repository / "tracked").write_text("exact\n", encoding="ascii")
        subprocess.run(["/usr/bin/git", "add", "tracked"], cwd=repository, check=True)
        subprocess.run(["/usr/bin/git", "commit", "-qm", "fixture"], cwd=repository, check=True)
        revision = subprocess.check_output(
            ["/usr/bin/git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        return repository, revision

    def source_gate(self, repository: Path, revision: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/python3", "-I", str(ROOT / "scripts/verify_source_tree.py"), revision],
            cwd=repository,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_source_gate_accepts_exact_commit_and_rejects_tracked_and_untracked_drift(self) -> None:
        repository, revision = self.make_git_repo()
        self.assertEqual(self.source_gate(repository, revision).returncode, 0)
        (repository / "tracked").write_text("dirty\n", encoding="ascii")
        self.assertEqual(self.source_gate(repository, revision).returncode, 2)
        (repository / "tracked").write_text("exact\n", encoding="ascii")
        (repository / "untracked").write_text("drift\n", encoding="ascii")
        self.assertEqual(self.source_gate(repository, revision).returncode, 2)

    def test_cleanup_refuses_intermediate_symlink(self) -> None:
        runtime = self.root / ".tmp" / "opswarden-e2e.ABCDEFGH"
        outside = self.root / "outside"
        runtime.mkdir(parents=True)
        outside.mkdir()
        secret = outside / "master.key"
        secret.write_text("protected\n", encoding="ascii")
        secret.chmod(0o600)
        (runtime / "restore").symlink_to(outside, target_is_directory=True)
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/cleanup_e2e_secrets.py"),
                str(runtime),
                "restore/master.key",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(secret.exists())

    def make_runner_fixture(self) -> tuple[Path, dict[str, str]]:
        fixture = self.root / "runner"
        scripts = fixture / "scripts"
        tests = fixture / "tests/e2e"
        binary = fixture / "bin"
        scripts.mkdir(parents=True)
        tests.mkdir(parents=True)
        binary.mkdir()
        for name in (
            "verify-e2e.sh",
            "scan-sensitive-fixtures.sh",
            "scan_sensitive_fixtures.py",
            "cleanup_e2e_secrets.py",
        ):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        (binary / "node").write_text("#!/bin/sh\nprintf '31001 31002\\n'\n", encoding="ascii")
        (binary / "docker").write_text(
            "#!/bin/sh\n"
            "if [ \"$1 $2\" = 'network ls' ]; then\n"
            "  [ \"${FAKE_ALL_SUBNETS:-}\" = 1 ] && printf 'occupied\\n'\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1 $2\" = 'network inspect' ] && [ \"${FAKE_ALL_SUBNETS:-}\" = 1 ]; then\n"
            "  second=20\n"
            "  while [ \"$second\" -le 27 ]; do\n"
            "    third=0\n"
            "    while [ \"$third\" -le 255 ]; do\n"
            "      printf '172.%s.%s.0/29\\n' \"$second\" \"$third\"\n"
            "      third=$((third + 1))\n"
            "    done\n"
            "    second=$((second + 1))\n"
            "  done\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="ascii",
        )
        (binary / "npm").write_text(
            "#!/bin/sh\n"
            "touch \"$(dirname \"$0\")/../npm-started\"\n"
            "sleep 30\n",
            encoding="ascii",
        )
        (binary / "npx").write_text("#!/bin/sh\nsleep 30\n", encoding="ascii")
        for item in binary.iterdir():
            item.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{binary}:/usr/bin:/bin",
            "OPSWARDEN_E2E_IMAGE_VERSION": "e2e-" + "a" * 40,
        }
        return fixture, environment

    def start_runner(self, fixture: Path, environment: dict[str, str]) -> subprocess.Popen[str]:
        return subprocess.Popen(
            ["/bin/bash", str(fixture / "scripts/verify-e2e.sh")],
            cwd=fixture,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def assert_signal_exit(self, sent: signal.Signals, expected: int) -> None:
        fixture, environment = self.make_runner_fixture()
        process = self.start_runner(fixture, environment)
        assert process.stdout is not None
        identifiers = process.stdout.readline()
        self.assertIn("runtime=", identifiers)
        marker = fixture / "npm-started"
        for _ in range(100):
            if marker.exists():
                break
            time.sleep(0.05)
        self.assertTrue(marker.exists())
        os.killpg(process.pid, sent)
        try:
            _, stderr = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        self.assertEqual(process.returncode, expected, stderr)
        runtime = Path(identifiers.split("runtime=", 1)[1].split(" artifact=", 1)[0])
        self.assertFalse((runtime / "master.key").exists())
        self.assertFalse((fixture / ".tmp/opswarden-e2e.global-lock").exists())

    def test_term_exit_is_nonzero_after_scan_and_cleanup(self) -> None:
        self.assert_signal_exit(signal.SIGTERM, 143)

    def test_interrupt_exit_is_nonzero_after_scan_and_cleanup(self) -> None:
        self.assert_signal_exit(signal.SIGINT, 130)

    def test_concurrent_runner_is_rejected_by_global_lock(self) -> None:
        fixture, environment = self.make_runner_fixture()
        first = self.start_runner(fixture, environment)
        assert first.stdout is not None
        first.stdout.readline()
        marker = fixture / "npm-started"
        for _ in range(100):
            if marker.exists():
                break
            time.sleep(0.05)
        self.assertTrue(marker.exists())
        second = self.start_runner(fixture, environment)
        _, second_stderr = second.communicate(timeout=10)
        self.assertEqual(second.returncode, 75, second_stderr)
        os.killpg(first.pid, signal.SIGTERM)
        first.communicate(timeout=15)
        self.assertFalse((fixture / ".tmp/opswarden-e2e.global-lock").exists())

    def test_subnet_collision_exhaustion_fails_closed_and_releases_lock(self) -> None:
        fixture, environment = self.make_runner_fixture()
        environment["FAKE_ALL_SUBNETS"] = "1"
        completed = subprocess.run(
            ["/bin/bash", str(fixture / "scripts/verify-e2e.sh")],
            cwd=fixture,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 75, completed.stderr)
        self.assertIn("no isolated backend subnet", completed.stderr)
        self.assertFalse((fixture / ".tmp/opswarden-e2e.global-lock").exists())

    def test_mcp_reporter_and_recovery_pattern_contracts_are_sanitized(self) -> None:
        harness = (ROOT / "tests/e2e/harness.ts").read_text(encoding="utf-8")
        setup = (ROOT / "tests/e2e/setup.ts").read_text(encoding="utf-8")
        self.assertIn("errors/mcp-failures.jsonl", harness)
        self.assertIn('bodyBase64: Buffer.from(body, "utf8").toString("base64")', harness)
        self.assertNotIn("status()}: ${body}", harness)
        self.assertNotIn("failed: ${body}", harness)
        self.assertIn("...bootstrap.recoveryCodes", setup)
        self.assertNotIn("recoveryCodes: bootstrap.recoveryCodes", setup)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/verify-e2e.sh").read_text(encoding="utf-8")
        self.assertIn("git archive --format=tar $(E2E_REVISION) | docker build", makefile)
        self.assertIn("verify_source_tree.py $(E2E_REVISION)", makefile)
        self.assertIn("E2E runtime=%s artifact=%s project=%s", runner)


if __name__ == "__main__":
    unittest.main(verbosity=2)
