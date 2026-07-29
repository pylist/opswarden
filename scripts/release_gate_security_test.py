#!/usr/bin/env python3
from __future__ import annotations

import os
import io
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import tarfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ReleaseGateSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="opswarden-gate-test-")
        self.root = Path(self.temporary.name).resolve()

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

    def test_real_replace_ref_cannot_change_verified_or_archived_commit(self) -> None:
        repository, original = self.make_git_repo()
        (repository / "tracked").write_text("replacement\n", encoding="ascii")
        subprocess.run(["/usr/bin/git", "commit", "-qam", "replacement"], cwd=repository, check=True)
        revision = subprocess.check_output(
            ["/usr/bin/git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        subprocess.run(["/usr/bin/git", "replace", revision, original], cwd=repository, check=True)
        default_body = subprocess.check_output(
            ["/usr/bin/git", "show", f"{revision}:tracked"], cwd=repository
        )
        self.assertEqual(default_body, b"exact\n")
        self.assertEqual(self.source_gate(repository, revision).returncode, 0)
        archive = subprocess.check_output(
            [
                "/usr/bin/env",
                "GIT_NO_REPLACE_OBJECTS=1",
                "/usr/bin/git",
                "--no-replace-objects",
                "archive",
                "--format=tar",
                revision,
            ],
            cwd=repository,
        )
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            handle = bundle.extractfile("tracked")
            self.assertIsNotNone(handle)
            self.assertEqual(handle.read(), b"replacement\n")
        (repository / "tracked").write_text("replacement\n", encoding="ascii")
        (repository / "untracked").write_text("drift\n", encoding="ascii")
        self.assertEqual(self.source_gate(repository, revision).returncode, 2)

    def test_cleanup_refuses_intermediate_symlink(self) -> None:
        runtime = self.root / ".tmp" / "opswarden-e2e.ABCDEFGH"
        outside = self.root / "outside"
        runtime.mkdir(parents=True)
        runtime.chmod(0o700)
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

    def test_cleanup_refuses_symlinked_tmp_component(self) -> None:
        real_tmp = self.root / "real-tmp"
        runtime = real_tmp / "opswarden-e2e.ABCDEFGH"
        runtime.mkdir(parents=True)
        runtime.chmod(0o700)
        secret = runtime / "master.key"
        secret.write_text("protected\n", encoding="ascii")
        secret.chmod(0o600)
        (self.root / ".tmp").symlink_to(real_tmp, target_is_directory=True)
        lexical_runtime = self.root / ".tmp" / runtime.name
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/cleanup_e2e_secrets.py"),
                str(lexical_runtime),
                "master.key",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(secret.exists())

    def make_runner_fixture(self, all_subnets: bool = False) -> tuple[Path, dict[str, str]]:
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
            "e2e_lock.py",
            "bounded_command.py",
            "write_e2e_artifact.py",
        ):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        (binary / "node").write_text("#!/bin/sh\nprintf '31001 31002\\n'\n", encoding="ascii")
        collision_script = (
            "printf 'abc123def456\\n'\n" if all_subnets else ""
        )
        inspect_script = (
            "second=20\n"
            "while [ \"$second\" -le 27 ]; do\n"
            "  third=0\n"
            "  while [ \"$third\" -le 255 ]; do\n"
            "    printf '172.%s.%s.0/29\\n' \"$second\" \"$third\"\n"
            "    third=$((third + 1))\n"
            "  done\n"
            "  second=$((second + 1))\n"
            "done\n"
            if all_subnets
            else ""
        )
        (binary / "docker").write_text(
            "#!/bin/sh\n"
            "if [ \"$1 $2\" = 'network ls' ]; then\n"
            f"  {collision_script or ':'}\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1 $2\" = 'network inspect' ]; then\n"
            f"{inspect_script}"
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="ascii",
        )
        (binary / "ready_child.py").write_text(
            "#!/usr/bin/python3\n"
            "import os,pathlib,signal,sys\n"
            "lock=os.stat(sys.argv[2])\n"
            "for number in range(3,256):\n"
            " try:\n"
            "  opened=os.fstat(number)\n"
            " except OSError:\n"
            "  continue\n"
            " if (opened.st_dev,opened.st_ino)==(lock.st_dev,lock.st_ino):\n"
            "  raise SystemExit(3)\n"
            "pathlib.Path(sys.argv[1]).touch()\n"
            "signal.pause()\n",
            encoding="ascii",
        )
        (binary / "npm").write_text(
            "#!/bin/sh\n"
            "exec /usr/bin/python3 -I \"$(dirname \"$0\")/ready_child.py\" "
            "\"$(dirname \"$0\")/../npm-started\" "
            "\"$(dirname \"$0\")/../.tmp/opswarden-e2e.lock\"\n",
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
            [
                "/usr/bin/python3",
                "-I",
                str(fixture / "scripts/e2e_lock.py"),
                str(fixture),
                "--",
                "/bin/bash",
                str(fixture / "scripts/verify-e2e.sh"),
            ],
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
        process.send_signal(sent)
        try:
            _, stderr = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, expected, stderr)
        runtime = Path(identifiers.split("runtime=", 1)[1].split(" artifact=", 1)[0])
        self.assertFalse((runtime / "master.key").exists())
        self.assertTrue((fixture / ".tmp/opswarden-e2e.lock").exists())

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
        first.send_signal(signal.SIGTERM)
        first.communicate(timeout=15)
        self.assertTrue((fixture / ".tmp/opswarden-e2e.lock").exists())

    def child_pid(self, parent: subprocess.Popen[str]) -> int:
        for _ in range(100):
            completed = subprocess.run(
                ["/bin/ps", "-axo", "pid=,ppid="],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            for line in completed.stdout.splitlines():
                values = line.split()
                if len(values) == 2 and int(values[1]) == parent.pid:
                    return int(values[0])
            time.sleep(0.05)
        self.fail("supervised runner child did not appear")

    def test_single_runner_pid_kill_releases_lock_for_restart(self) -> None:
        runner = self.root / "single-runner.py"
        marker = self.root / "single-runner-ready"
        runner.write_text(
            "#!/usr/bin/python3\n"
            "import pathlib,signal,sys\n"
            "pathlib.Path(sys.argv[1]).touch()\n"
            "signal.pause()\n",
            encoding="ascii",
        )
        runner.chmod(0o755)
        lock_command = [
            "/usr/bin/python3",
            "-I",
            str(ROOT / "scripts/e2e_lock.py"),
            str(self.root),
            "--",
        ]
        first = subprocess.Popen(
            [*lock_command, str(runner), str(marker)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            if marker.exists():
                break
            time.sleep(0.05)
        self.assertTrue(marker.exists())
        runner_pid = self.child_pid(first)
        os.kill(runner_pid, signal.SIGKILL)
        _, first_stderr = first.communicate(timeout=10)
        self.assertEqual(first.returncode, 137, first_stderr)
        second = subprocess.run(
            [*lock_command, "/usr/bin/true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_forged_legacy_lock_environment_cannot_bypass_parent_lock(self) -> None:
        fixture, environment = self.make_runner_fixture()
        first = self.start_runner(fixture, environment)
        assert first.stdout is not None
        first.stdout.readline()
        marker = fixture / "npm-started"
        for _ in range(100):
            if marker.exists():
                break
            time.sleep(0.05)
        forged = {**environment, "OPSWARDEN_E2E_LOCK_HELD": "1"}
        second = self.start_runner(fixture, forged)
        _, stderr = second.communicate(timeout=10)
        self.assertEqual(second.returncode, 75, stderr)
        first.send_signal(signal.SIGTERM)
        first.communicate(timeout=15)

    def test_subnet_collision_exhaustion_fails_closed_and_releases_lock(self) -> None:
        fixture, environment = self.make_runner_fixture(all_subnets=True)
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(fixture / "scripts/e2e_lock.py"),
                str(fixture),
                "--",
                "/bin/bash",
                str(fixture / "scripts/verify-e2e.sh"),
            ],
            cwd=fixture,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 75, completed.stderr)
        self.assertIn("no isolated backend subnet", completed.stderr)
        self.assertTrue((fixture / ".tmp/opswarden-e2e.lock").exists())

    def test_mcp_reporter_and_recovery_pattern_contracts_are_sanitized(self) -> None:
        harness = (ROOT / "tests/e2e/harness.ts").read_text(encoding="utf-8")
        setup = (ROOT / "tests/e2e/setup.ts").read_text(encoding="utf-8")
        self.assertIn("errors/mcp-failures.bin", harness)
        self.assertIn("scripts/write_e2e_artifact.py", harness)
        self.assertIn('child.stdin.on("error"', harness)
        self.assertIn("child.stdin.end(body, (error?: Error | null) =>", harness)
        self.assertNotIn("bodyBase64", harness)
        self.assertNotIn("status()}: ${body}", harness)
        self.assertNotIn("failed: ${body}", harness)
        self.assertIn("...bootstrap.recoveryCodes", setup)
        self.assertNotIn("recoveryCodes: bootstrap.recoveryCodes", setup)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/verify-e2e.sh").read_text(encoding="utf-8")
        self.assertIn("git --no-replace-objects archive --format=tar $(E2E_REVISION)", makefile)
        self.assertIn("GIT_NO_REPLACE_OBJECTS=1", makefile)
        self.assertIn("verify_source_tree.py $(E2E_REVISION)", makefile)
        self.assertIn("E2E runtime=%s artifact=%s project=%s", runner)
        self.assertNotIn("OPSWARDEN_E2E_LOCK_HELD", runner)
        self.assertIn("_verify-locked", makefile)
        self.assertIn("scripts/e2e_lock.py", makefile)

    def test_release_gate_pins_go_vulnerability_scan_and_audits_both_node_locks(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        vulnerability_scan = (
            "GOTOOLCHAIN=go1.25.12 "
            "go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./..."
        )
        web_install = "cd web && npm ci --no-audit --no-fund"
        web_audit = "cd web && npm audit --audit-level=moderate"
        e2e_audit = "cd tests/e2e && npm audit --audit-level=moderate"
        self.assertEqual(makefile.count(vulnerability_scan), 1)
        self.assertEqual(makefile.count(web_audit), 1)
        self.assertEqual(makefile.count(e2e_audit), 1)
        self.assertLess(makefile.index(web_install), makefile.index(web_audit))
        self.assertNotIn("npm audit --omit=dev", makefile)
        self.assertNotIn("govulncheck@latest", makefile)
        self.assertNotIn("npm audit --audit-level=high", makefile)

    def test_e2e_splits_real_jwt_sessions_and_fails_fast_on_sanitized_429s(self) -> None:
        harness = (ROOT / "tests/e2e/harness.ts").read_text(encoding="utf-8")
        budget = (ROOT / "tests/e2e/request-budget.mjs").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("loginWithTOTPAsNewSession", harness)
        self.assertIn('this.uiSession = "ui-session-2"', harness)
        self.assertIn("this.requestBudget.failure.then", harness)
        self.assertIn("audit/ui-request-budget.json", harness)
        self.assertNotIn("${rawURL}", budget)
        self.assertIn("node --test tests/e2e/request-budget.test.mjs", makefile)

    def test_primary_e2e_uses_full_tls_compose_release_topology(self) -> None:
        runner = (ROOT / "scripts/verify-e2e.sh").read_text(encoding="utf-8")
        server = (ROOT / "tests/e2e/server.mjs").read_text(encoding="utf-8")
        setup = (ROOT / "tests/e2e/setup.ts").read_text(encoding="utf-8")
        config = (ROOT / "tests/e2e/playwright.config.ts").read_text(encoding="utf-8")
        compose = (ROOT / "deploy/compose.yaml").read_text(encoding="utf-8")

        self.assertNotIn('spawnSync("go", ["build"', server)
        self.assertIn('"up", "-d", "--no-build"', server)
        self.assertIn('"opswarden", "caddy"', server)
        self.assertIn("org.opencontainers.image.revision", server)
        self.assertIn("NetworkSettings.Ports", server)
        self.assertIn("https://localhost:", setup)
        self.assertIn("https://localhost:", config)
        self.assertIn("ignoreHTTPSErrors: true", config)
        self.assertIn("tls internal", server)
        self.assertIn("import /etc/caddy/OpsWardenProxy.caddy", server)
        self.assertIn("import opswarden_proxy", server)
        self.assertNotIn("Content-Security-Policy", server)
        self.assertNotIn("reverse_proxy opswarden:8080", server)
        self.assertIn('- "443:443/tcp"', compose)
        self.assertIn("ports: !override", server)
        self.assertIn("volumes: !override", server)
        self.assertIn('OPSWARDEN_E2E_BASE_URL="https://localhost:', runner)
        self.assertIn('tests/e2e/cleanup.mjs"', runner)
        cleanup = (ROOT / "tests/e2e/cleanup.mjs").read_text(encoding="utf-8")
        self.assertIn('"down", "--volumes", "--remove-orphans"', cleanup)
        self.assertIn("`${project}-release`", cleanup)
        self.assertIn("`${project}-wrong`", cleanup)

    def test_production_caddy_config_is_baked_validated_and_shared_with_e2e(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        dockerfile = (ROOT / "deploy/Caddy.Dockerfile").read_text(encoding="utf-8")
        production = (ROOT / "deploy/Caddyfile").read_text(encoding="utf-8")
        shared = (ROOT / "deploy/OpsWardenProxy.caddy").read_text(encoding="utf-8")
        compose = (ROOT / "deploy/compose.yaml").read_text(encoding="utf-8")
        server = (ROOT / "tests/e2e/server.mjs").read_text(encoding="utf-8")

        self.assertIn("COPY deploy/Caddyfile /etc/caddy/Caddyfile", dockerfile)
        self.assertIn(
            "COPY deploy/OpsWardenProxy.caddy /etc/caddy/OpsWardenProxy.caddy",
            dockerfile,
        )
        validate = (
            "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
        )
        self.assertEqual(dockerfile.count(validate), 1)
        self.assertLess(dockerfile.index("COPY deploy/Caddyfile"), dockerfile.index(validate))
        self.assertIn("docker build -f deploy/Caddy.Dockerfile", makefile)
        self.assertIn(
            "validate --config /etc/caddy/Caddyfile --adapter caddyfile",
            makefile,
        )
        self.assertIn(
            "adapt --validate --config /etc/caddy/Caddyfile --adapter caddyfile",
            makefile,
        )
        self.assertIn(
            "! printf '%s\\n' 'malformed {' | docker run",
            makefile,
        )
        self.assertIn(
            "adapt --validate --config - --adapter caddyfile",
            makefile,
        )
        self.assertIn("import /etc/caddy/OpsWardenProxy.caddy", production)
        self.assertIn("import opswarden_proxy", production)
        self.assertIn("Content-Security-Policy", shared)
        self.assertIn("reverse_proxy opswarden:8080", shared)
        self.assertIn('OPSWARDEN_FORWARDED_FOR: "{remote_host}"', compose)
        self.assertNotIn("${OPSWARDEN_FORWARDED_FOR", compose)
        self.assertIn("OPSWARDEN_FORWARDED_FOR: 127.0.0.1", server)
        self.assertNotIn("source: ./Caddyfile", compose)

    def test_mcp_artifact_symlink_cannot_write_outside(self) -> None:
        artifact = self.root / "artifact"
        errors = artifact / "errors"
        errors.mkdir(parents=True)
        artifact.chmod(0o700)
        errors.chmod(0o700)
        outside = self.root / "outside"
        outside.write_bytes(b"unchanged")
        outside.chmod(0o600)
        (errors / "mcp-failures.bin").symlink_to(outside)
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/write_e2e_artifact.py"),
                str(artifact),
                "errors/mcp-failures.bin",
            ],
            input=b"secret body",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(outside.read_bytes(), b"unchanged")
        (errors / "mcp-failures.bin").unlink()
        body = b"raw protected MCP body"
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/write_e2e_artifact.py"),
                str(artifact),
                "errors/mcp-failures.bin",
            ],
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            (errors / "mcp-failures.bin").read_bytes(),
            len(body).to_bytes(8, "big") + body,
        )

    def test_mcp_artifact_hardlink_and_oversize_are_refused(self) -> None:
        artifact = self.root / "artifact-hardlink"
        errors = artifact / "errors"
        errors.mkdir(parents=True)
        artifact.chmod(0o700)
        errors.chmod(0o700)
        outside = self.root / "outside-hardlink"
        outside.write_bytes(b"unchanged")
        outside.chmod(0o600)
        os.link(outside, errors / "mcp-failures.bin")
        command = [
            "/usr/bin/python3",
            "-I",
            str(ROOT / "scripts/write_e2e_artifact.py"),
            str(artifact),
            "errors/mcp-failures.bin",
        ]
        completed = subprocess.run(
            command,
            input=b"must not escape",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(outside.read_bytes(), b"unchanged")
        (errors / "mcp-failures.bin").unlink()
        completed = subprocess.run(
            command,
            input=b"x" * ((4 << 20) + 1),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual((errors / "mcp-failures.bin").read_bytes(), b"")

    def test_lock_refuses_symlinked_tmp_component(self) -> None:
        real_tmp = self.root / "real-lock-tmp"
        real_tmp.mkdir()
        (self.root / ".tmp").symlink_to(real_tmp, target_is_directory=True)
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/e2e_lock.py"),
                str(self.root),
                "--",
                "/usr/bin/true",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 75)

    def test_supervisor_kills_ignore_term_group_before_releasing_lock(self) -> None:
        child = self.root / "ignore-term.py"
        ready = self.root / "ignore-term-ready"
        child.write_text(
            "#!/usr/bin/python3\n"
            "import pathlib,signal,sys\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[1]).touch()\n"
            "signal.pause()\n",
            encoding="ascii",
        )
        child.chmod(0o755)
        command = [
            "/usr/bin/python3",
            "-I",
            str(ROOT / "scripts/e2e_lock.py"),
            str(self.root),
            "--",
            str(child),
            str(ready),
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(0.05)
        self.assertTrue(ready.exists())
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=8)
        self.assertEqual(process.returncode, 143)
        self.assertLess(time.monotonic() - started, 7)
        reacquired = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/e2e_lock.py"),
                str(self.root),
                "--",
                "/usr/bin/true",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(reacquired.returncode, 0, reacquired.stderr)

    def test_bounded_command_terminates_unresponsive_child(self) -> None:
        child = self.root / "unresponsive.py"
        child.write_text(
            "#!/usr/bin/python3\n"
            "import signal\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "signal.pause()\n",
            encoding="ascii",
        )
        child.chmod(0o755)
        started = time.monotonic()
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(ROOT / "scripts/bounded_command.py"),
                "1",
                str(child),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertLess(time.monotonic() - started, 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
