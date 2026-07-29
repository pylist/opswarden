#!/usr/bin/env python3
"""Fail-closed offline snapshot and restore preflight helpers."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


PRODUCTION_DB = Path("/srv/opswarden/state/data/opswarden.db")
PREUPGRADE_DIR = Path("/srv/opswarden/preupgrade")
RESTORE_CHECKOUT = Path("/srv/opswarden-restore-worktree/source")
RESTORE_DB = Path("/srv/opswarden-restore/state/data/opswarden.db")
RESTORE_ENV = Path("/srv/opswarden-restore/restore.env")
TRUSTED_OPS_HELPER = Path("/usr/local/libexec/opswarden/offline_ops.py")
PRODUCTION_STATE = Path("/srv/opswarden/state")
PRODUCTION_KEY = Path("/srv/opswarden/secrets/master.key")
OPSWARDEN_UID = 10001
OPSWARDEN_GID = 10001
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
RELEASE_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,254}")
GIT_BINARY = "/usr/bin/git"
SQLITE_BINARY = "/usr/bin/sqlite3"
RESTORE_ENV_KEYS = {
    "OPSWARDEN_HOSTNAME",
    "OPSWARDEN_TLS_EMAIL",
    "OPSWARDEN_VERSION",
    "OPSWARDEN_REVISION",
    "SOURCE_DATE_EPOCH",
    "OPSWARDEN_STATE_PATH",
    "OPSWARDEN_MASTER_KEY_PATH",
    "CADDY_DATA_PATH",
    "CADDY_CONFIG_PATH",
    "OPSWARDEN_BACKEND_SUBNET",
    "OPSWARDEN_APP_IP",
    "OPSWARDEN_CADDY_IP",
    "OPSWARDEN_INTERNAL_CIDRS",
    "OPSWARDEN_RESTORE_HOST_PORT",
}
ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def git_command(checkout: Path, *arguments: str) -> list[str]:
    return [
        GIT_BINARY,
        "--no-replace-objects",
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
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def verify_trusted_helper(
    path: Path,
    expected_path: Path,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    path = Path(path)
    expected_path = Path(expected_path)
    if path != expected_path or path.resolve(strict=True) != expected_path:
        raise PermissionError("helper is not executing from its fixed trust anchor")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("trusted helper must be a regular non-symlink file")
    if (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_size <= 0
    ):
        raise PermissionError("trusted helper ownership or mode is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("trusted helper changed while opening")
    finally:
        os.close(descriptor)


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


def parse_environment_file(
    path: Path, expected_uid: int, expected_gid: int
) -> dict[str, str]:
    metadata = assert_secure_regular(
        path, expected_uid, expected_gid, PRIVATE_FILE_MODE
    )
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("restore environment changed while opening")
        chunks = bytearray()
        while len(chunks) <= 16 * 1024:
            chunk = os.read(descriptor, min(4096, 16 * 1024 + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > 16 * 1024 or b"\x00" in raw or b"\r" in raw:
        raise ValueError("restore environment file has invalid encoding or size")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("restore environment file must be ASCII") from error
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line.strip() != line or "=" not in line:
            raise ValueError(f"invalid environment syntax on line {line_number}")
        key, value = line.split("=", 1)
        if ENV_KEY_RE.fullmatch(key) is None or key not in RESTORE_ENV_KEYS:
            raise ValueError(f"unknown restore environment key on line {line_number}")
        if key in values:
            raise ValueError(f"duplicate restore environment key on line {line_number}")
        if any(character in value for character in ("$", "`", "\\", "'", '"')):
            raise ValueError(f"unsafe restore environment value on line {line_number}")
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ValueError(f"invalid restore environment value on line {line_number}")
        values[key] = value
    if set(values) != RESTORE_ENV_KEYS:
        raise ValueError("restore environment keys are incomplete")
    return values


def verify_restore_environment(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    release_tag: str,
    expected_revision: str,
    expected_epoch: int,
) -> None:
    values = parse_environment_file(path, expected_uid, expected_gid)
    expected_version = release_tag[1:] if release_tag.startswith("v") else release_tag
    exact = {
        "OPSWARDEN_HOSTNAME": "localhost",
        "OPSWARDEN_VERSION": expected_version,
        "OPSWARDEN_REVISION": expected_revision,
        "SOURCE_DATE_EPOCH": str(expected_epoch),
        "OPSWARDEN_STATE_PATH": "/srv/opswarden-restore/state",
        "OPSWARDEN_MASTER_KEY_PATH": (
            "/srv/opswarden-restore/secrets/master.key"
        ),
        "CADDY_DATA_PATH": "/srv/opswarden-restore/caddy/data",
        "CADDY_CONFIG_PATH": "/srv/opswarden-restore/caddy/config",
        "OPSWARDEN_BACKEND_SUBNET": "172.31.251.0/29",
        "OPSWARDEN_APP_IP": "172.31.251.2",
        "OPSWARDEN_CADDY_IP": "172.31.251.3",
        "OPSWARDEN_INTERNAL_CIDRS": "",
        "OPSWARDEN_RESTORE_HOST_PORT": "127.0.0.1:8443:443/tcp",
    }
    for key, expected in exact.items():
        if values[key] != expected:
            raise ValueError(f"restore environment has invalid {key}")
    email = values["OPSWARDEN_TLS_EMAIL"]
    if (
        len(email) > 254
        or email.count("@") != 1
        or email.startswith("@")
        or email.endswith("@")
        or any(character.isspace() for character in email)
    ):
        raise ValueError("restore TLS notification email is invalid")
    state = Path(values["OPSWARDEN_STATE_PATH"])
    key = Path(values["OPSWARDEN_MASTER_KEY_PATH"])
    if (
        state == PRODUCTION_STATE
        or key == PRODUCTION_KEY
        or state.resolve(strict=False) == PRODUCTION_STATE
        or key.resolve(strict=False) == PRODUCTION_KEY
    ):
        raise ValueError("restore paths must not reference production")
    subnet = ipaddress.ip_network(values["OPSWARDEN_BACKEND_SUBNET"], strict=True)
    app_ip = ipaddress.ip_address(values["OPSWARDEN_APP_IP"])
    caddy_ip = ipaddress.ip_address(values["OPSWARDEN_CADDY_IP"])
    if app_ip not in subnet or caddy_ip not in subnet or app_ip == caddy_ip:
        raise ValueError("restore network addresses are inconsistent")


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


def reject_replace_refs(checkout: Path) -> None:
    result = subprocess.run(
        git_command(
            checkout, "for-each-ref", "--format=%(refname)", "refs/replace/"
        ),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if result.stdout:
        raise RuntimeError("repository contains forbidden replacement refs")


def verify_pristine_worktree(checkout: Path) -> None:
    flags = subprocess.run(
        git_command(checkout, "ls-files", "-v", "-z"),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    ).stdout
    for record in flags.split(b"\x00"):
        if record and not record.startswith(b"H "):
            raise RuntimeError("tracked file has forbidden index flags or state")
    ignored = subprocess.run(
        git_command(
            checkout,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    ).stdout
    if ignored:
        raise RuntimeError("isolated checkout contains ignored build inputs")
    difference = subprocess.run(
        git_command(checkout, "diff", "--no-ext-diff", "--quiet", "HEAD", "--"),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if difference.returncode != 0:
        raise RuntimeError("isolated checkout differs from signed HEAD")
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


def exact_git_line(checkout: Path, *arguments: str) -> str:
    result = subprocess.run(
        git_command(checkout, *arguments),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_environment(),
    ).stdout
    if not result.endswith("\n") or result.count("\n") != 1:
        raise RuntimeError("Git did not return one exact line")
    return result[:-1]


def verify_release_tag(
    checkout: Path, release_tag: str, expected_revision: str
) -> tuple[str, int]:
    if RELEASE_TAG_RE.fullmatch(release_tag) is None or release_tag.startswith("-"):
        raise ValueError("release tag has an unsafe or invalid form")
    tag_ref = f"refs/tags/{release_tag}"
    if exact_git_line(checkout, "cat-file", "-t", tag_ref) != "tag":
        raise RuntimeError("release reference must be an annotated tag")
    verification = subprocess.run(
        git_command(checkout, "verify-tag", "--raw", tag_ref),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if verification.returncode != 0:
        raise RuntimeError("release tag signature verification failed")
    resolved = exact_git_line(checkout, "rev-parse", f"{tag_ref}^{{commit}}")
    if not hmac.compare_digest(resolved, expected_revision):
        raise RuntimeError("release tag does not resolve to the recorded revision")
    release_tree = exact_git_line(
        checkout, "rev-parse", f"{tag_ref}^{{commit}}^{{tree}}"
    )
    if GIT_REVISION_RE.fullmatch(release_tree) is None:
        raise RuntimeError("release tag tree is not a full object ID")
    epoch_text = exact_git_line(
        checkout, "show", "-s", "--format=%ct", expected_revision
    )
    if not epoch_text.isdecimal():
        raise RuntimeError("release commit epoch is invalid")
    return release_tree, int(epoch_text)


def restore_preflight(
    checkout: Path,
    release_tag: str,
    expected_revision: str,
    snapshot: Path,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
    env_path: Path | None = None,
    operator_uid: int | None = None,
    operator_gid: int | None = None,
) -> None:
    if GIT_REVISION_RE.fullmatch(expected_revision) is None:
        raise ValueError("expected Git revision must be a full lowercase object ID")
    checkout = Path(checkout)
    if operator_uid is None:
        operator_uid = os.lstat(checkout).st_uid
    if operator_gid is None:
        operator_gid = os.lstat(checkout).st_gid
    assert_private_directory(checkout.parent, operator_uid, operator_gid)
    assert_private_directory(checkout, operator_uid, operator_gid)
    reject_replace_refs(checkout)
    actual_revision = exact_checkout_revision(checkout)
    if not hmac.compare_digest(actual_revision, expected_revision):
        raise RuntimeError("isolated checkout revision does not match the recorded revision")
    release_tree, release_epoch = verify_release_tag(
        checkout, release_tag, expected_revision
    )
    head_tree = exact_git_line(checkout, "rev-parse", "HEAD^{tree}")
    if (
        GIT_REVISION_RE.fullmatch(head_tree) is None
        or not hmac.compare_digest(head_tree, release_tree)
    ):
        raise RuntimeError("worktree HEAD tree does not match the signed release")
    verify_pristine_worktree(checkout)
    if env_path is not None:
        verify_restore_environment(
            env_path,
            operator_uid,
            operator_gid,
            release_tag,
            expected_revision,
            release_epoch,
        )
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
    release_tag: str,
    expected_revision: str,
    expected_sha256: str,
    env_path: str,
    operator_uid: str,
    operator_gid: str,
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("restore preflight must run as root")
    if not operator_uid.isdecimal() or not operator_gid.isdecimal():
        raise ValueError("restore operator UID and GID must be decimal")
    if int(operator_uid) == 0:
        raise PermissionError("restore operator UID must be non-root")
    if Path(env_path) != RESTORE_ENV:
        raise ValueError("restore preflight requires the fixed Compose env file")
    restore_preflight(
        RESTORE_CHECKOUT,
        release_tag,
        expected_revision,
        RESTORE_DB,
        expected_sha256,
        OPSWARDEN_UID,
        OPSWARDEN_GID,
        Path(env_path),
        int(operator_uid),
        int(operator_gid),
    )
    print("restore preflight: exact revision, checksum, and integrity verified")


def main(argv: list[str]) -> int:
    try:
        verify_trusted_helper(Path(__file__), TRUSTED_OPS_HELPER)
        if argv == ["snapshot"]:
            snapshot_command()
        elif len(argv) == 7 and argv[0] == "restore-preflight":
            restore_preflight_command(
                argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]
            )
        else:
            raise ValueError(
                "usage: offline_ops.py snapshot | "
                "restore-preflight RELEASE_TAG EXPECTED_REVISION RECORDED_SHA256 "
                "ENV_FILE OPERATOR_UID OPERATOR_GID"
            )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"offline operation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
