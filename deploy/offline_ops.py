#!/usr/bin/env python3
"""Fail-closed offline snapshot and restore preflight helpers."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


PRODUCTION_DB = Path("/srv/opswarden/state/data/opswarden.db")
PREUPGRADE_DIR = Path("/srv/opswarden/preupgrade")
RESTORE_CHECKOUT = Path("/srv/opswarden-restore/source")
RESTORE_DB = Path("/srv/opswarden-restore/state/data/opswarden.db")
OPSWARDEN_UID = 10001
OPSWARDEN_GID = 10001
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
RELEASE_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,254}")
GIT_BINARY = "/usr/bin/git"
SQLITE_BINARY = "/usr/bin/sqlite3"


def git_command(checkout: Path, *arguments: str) -> list[str]:
    return [
        GIT_BINARY,
        "-c",
        f"safe.directory={checkout}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "gpg.format=openpgp",
        "-c",
        "gpg.program=/usr/bin/gpg",
        "-C",
        str(checkout),
        *arguments,
    ]


def git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key != "GNUPGHOME"
    }
    environment["PATH"] = "/usr/bin:/bin"
    return environment


def assert_secure_regular(
    path: Path, expected_uid: int, expected_gid: int, expected_mode: int
) -> os.stat_result:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("path must be a regular non-symlink file")
    if metadata.st_size <= 0:
        raise ValueError("file must be nonempty")
    if path.resolve(strict=True) != path:
        raise ValueError("path must already be canonical")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise PermissionError("file ownership does not match the service account")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise PermissionError("file mode does not match the required private mode")
    return metadata


def assert_private_directory(
    path: Path, expected_uid: int, expected_gid: int
) -> os.stat_result:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("path must be a directory, not a symlink")
    if path.resolve(strict=True) != path:
        raise ValueError("directory path must already be canonical")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise PermissionError("directory ownership does not match the service account")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise PermissionError("directory mode must be 0700")
    return metadata


def verify_integrity(path: Path) -> None:
    path = Path(path)
    uri = f"file:{path}?mode=ro&immutable=1"
    result = subprocess.run(
        [SQLITE_BINARY, uri, "PRAGMA integrity_check;"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("SQLite integrity command failed")
    # sqlite3 emits exactly one result line. Do not strip or accept extra output.
    if result.stdout != b"ok\n":
        raise RuntimeError("SQLite integrity_check did not return exact ok")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected_sha256: str) -> None:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, expected_sha256):
        raise RuntimeError("snapshot SHA-256 does not match the recorded value")


def sqlite_cli_quote(value: str) -> str:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("unsafe path")
    return "'" + value.replace("'", "''") + "'"


def create_snapshot(
    source: Path,
    snapshot: Path,
    manifest: Path,
    expected_uid: int,
    expected_gid: int,
) -> str:
    source = Path(source)
    snapshot = Path(snapshot)
    manifest = Path(manifest)
    source_metadata = assert_secure_regular(
        source, expected_uid, expected_gid, PRIVATE_FILE_MODE
    )
    assert_private_directory(snapshot.parent, expected_uid, expected_gid)
    if manifest.parent != snapshot.parent:
        raise ValueError("manifest and snapshot must share the private directory")
    if os.path.lexists(snapshot) or os.path.lexists(manifest):
        raise FileExistsError("snapshot or manifest already exists")
    verify_integrity(source)

    previous_umask = os.umask(0o077)
    try:
        command = f".timeout 5000\n.backup {sqlite_cli_quote(str(snapshot))}\n"
        result = subprocess.run(
            [SQLITE_BINARY, str(source)],
            input=command,
            text=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        os.umask(previous_umask)
    if result.returncode != 0:
        if os.path.lexists(snapshot) and not snapshot.is_symlink():
            snapshot.unlink()
        raise RuntimeError("SQLite .backup failed")

    try:
        source_after = assert_secure_regular(
            source, expected_uid, expected_gid, PRIVATE_FILE_MODE
        )
        if (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_mtime_ns,
        ) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_size,
            source_metadata.st_mtime_ns,
        ):
            raise RuntimeError("source database changed during snapshot")
        os.chmod(snapshot, PRIVATE_FILE_MODE, follow_symlinks=False)
        assert_secure_regular(
            snapshot, expected_uid, expected_gid, PRIVATE_FILE_MODE
        )
        verify_integrity(snapshot)
        digest = sha256_file(snapshot)

        descriptor = os.open(
            manifest,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            PRIVATE_FILE_MODE,
        )
        try:
            payload = f"{digest}  {snapshot.name}\n".encode("ascii")
            written = os.write(descriptor, payload)
            if written != len(payload):
                raise OSError("short checksum manifest write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        assert_secure_regular(
            manifest, expected_uid, expected_gid, PRIVATE_FILE_MODE
        )
        directory_fd = os.open(
            snapshot.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return digest
    except BaseException:
        for partial in (manifest, snapshot):
            if os.path.lexists(partial) and not partial.is_symlink():
                partial.unlink()
        raise


def exact_checkout_revision(checkout: Path) -> str:
    checkout = Path(checkout)
    if not checkout.is_absolute() or checkout.resolve(strict=True) != checkout:
        raise ValueError("checkout path must be an existing canonical path")
    git_marker = checkout / ".git"
    marker = os.lstat(git_marker)
    if stat.S_ISLNK(marker.st_mode) or not stat.S_ISREG(marker.st_mode):
        raise ValueError("checkout must be an isolated linked Git worktree")
    result = subprocess.run(
        git_command(checkout, "rev-parse", "HEAD"),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_environment(),
    )
    if not result.stdout.endswith("\n") or result.stdout.count("\n") != 1:
        raise RuntimeError("Git did not return one exact HEAD revision")
    revision = result.stdout[:-1]
    if GIT_REVISION_RE.fullmatch(revision) is None:
        raise RuntimeError("Git HEAD is not a full object ID")
    symbolic = subprocess.run(
        git_command(checkout, "symbolic-ref", "-q", "HEAD"),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if symbolic.returncode != 1 or symbolic.stdout:
        raise RuntimeError("isolated checkout must have a detached HEAD")
    return revision


def verify_release_tag(
    checkout: Path, release_tag: str, expected_revision: str
) -> None:
    if RELEASE_TAG_RE.fullmatch(release_tag) is None or release_tag.startswith("-"):
        raise ValueError("release tag has an unsafe or invalid form")
    tag_ref = f"refs/tags/{release_tag}"
    verification = subprocess.run(
        git_command(checkout, "verify-tag", "--raw", tag_ref),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if verification.returncode != 0:
        raise RuntimeError("release tag signature verification failed")
    resolved = subprocess.run(
        git_command(checkout, "rev-parse", f"{tag_ref}^{{commit}}"),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_environment(),
    ).stdout
    if not resolved.endswith("\n") or resolved.count("\n") != 1:
        raise RuntimeError("release tag did not resolve to one exact revision")
    if not hmac.compare_digest(resolved[:-1], expected_revision):
        raise RuntimeError("release tag does not resolve to the recorded revision")


def restore_preflight(
    checkout: Path,
    release_tag: str,
    expected_revision: str,
    snapshot: Path,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if GIT_REVISION_RE.fullmatch(expected_revision) is None:
        raise ValueError("expected Git revision must be a full lowercase object ID")
    actual_revision = exact_checkout_revision(Path(checkout))
    if not hmac.compare_digest(actual_revision, expected_revision):
        raise RuntimeError("isolated checkout revision does not match the recorded revision")
    verify_release_tag(Path(checkout), release_tag, expected_revision)
    status = subprocess.run(
        git_command(
            checkout, "status", "--porcelain", "--untracked-files=all"
        ),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if status.stdout:
        raise RuntimeError("isolated checkout has tracked or untracked modifications")
    assert_secure_regular(
        Path(snapshot), expected_uid, expected_gid, PRIVATE_FILE_MODE
    )
    verify_checksum(Path(snapshot), expected_sha256)
    verify_integrity(Path(snapshot))


def snapshot_command() -> None:
    if os.geteuid() != OPSWARDEN_UID or os.getegid() != OPSWARDEN_GID:
        raise PermissionError("snapshot helper must run as 10001:10001")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = PREUPGRADE_DIR / f"opswarden-{stamp}.sqlite3"
    manifest = snapshot.with_suffix(snapshot.suffix + ".sha256")
    create_snapshot(
        PRODUCTION_DB,
        snapshot,
        manifest,
        OPSWARDEN_UID,
        OPSWARDEN_GID,
    )
    print(f"verified snapshot: {snapshot.name}")
    print(f"private checksum manifest: {manifest.name}")


def restore_preflight_command(
    release_tag: str, expected_revision: str, expected_sha256: str
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("restore preflight must run as root")
    restore_preflight(
        RESTORE_CHECKOUT,
        release_tag,
        expected_revision,
        RESTORE_DB,
        expected_sha256,
        OPSWARDEN_UID,
        OPSWARDEN_GID,
    )
    print("restore preflight: exact revision, checksum, and integrity verified")


def main(argv: list[str]) -> int:
    try:
        if argv == ["snapshot"]:
            snapshot_command()
        elif len(argv) == 4 and argv[0] == "restore-preflight":
            restore_preflight_command(argv[1], argv[2], argv[3])
        else:
            raise ValueError(
                "usage: offline_ops.py snapshot | "
                "restore-preflight RELEASE_TAG EXPECTED_REVISION RECORDED_SHA256"
            )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"offline operation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
