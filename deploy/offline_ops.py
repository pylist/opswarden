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
import tempfile


PRODUCTION_DB = Path("/srv/opswarden/state/data/opswarden.db")
PREUPGRADE_DIR = Path("/srv/opswarden/preupgrade")
RESTORE_RELEASE = Path("/srv/opswarden-restore/release")
RESTORE_RELEASE_MANIFEST = Path("/srv/opswarden-restore/release.manifest")
RESTORE_STAGING = Path("/srv/opswarden-restore-staging/release")
RESTORE_STAGING_MANIFEST = Path("/srv/opswarden-restore-staging/release.manifest")
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
SQLITE_BINARY = "/usr/bin/sqlite3"
MANIFEST_HEADER = "OPSWARDEN-RELEASE-MANIFEST-V1"
MANIFEST_PATH_RE = re.compile(r"[A-Za-z0-9._+@/-]{1,4096}")
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


def atomic_install_blob(
    source_descriptor: int,
    destination: Path,
    expected_sha256: str,
    expected_size: int,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Install only bytes from an already-open verified object stream."""
    destination = Path(destination)
    if (
        not destination.is_absolute()
        or destination.parent.resolve(strict=True) != destination.parent
        or SHA256_RE.fullmatch(expected_sha256) is None
        or expected_size <= 0
    ):
        raise ValueError("trusted blob install arguments are invalid")
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    try:
        while total <= expected_size:
            chunk = os.read(source_descriptor, min(1024 * 1024, expected_size + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_descriptor, view)
                if written <= 0:
                    raise OSError("short trusted blob write")
                view = view[written:]
        if total != expected_size or not hmac.compare_digest(
            digest.hexdigest(), expected_sha256
        ):
            raise RuntimeError("trusted object stream does not match signed blob")
        os.fchown(temporary_descriptor, expected_uid, expected_gid)
        os.fchmod(temporary_descriptor, 0o755)
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        os.replace(temporary, destination)
        directory_descriptor = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        installed = _read_exact_regular(
            destination, expected_uid, expected_gid, 0o755, expected_size
        )
        if len(installed) != expected_size or not hmac.compare_digest(
            hashlib.sha256(installed).hexdigest(), expected_sha256
        ):
            raise RuntimeError("installed trust anchor failed verification")
    except BaseException:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if os.path.lexists(temporary) and not temporary.is_symlink():
            temporary.unlink()
        raise


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


def _read_exact_regular(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    maximum_size: int,
) -> bytes:
    metadata = assert_secure_regular(path, expected_uid, expected_gid, expected_mode)
    if metadata.st_size > maximum_size:
        raise ValueError("trusted file is too large")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("trusted file changed while opening")
        chunks = bytearray()
        while len(chunks) <= maximum_size:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise RuntimeError("trusted file changed while reading")
    finally:
        os.close(descriptor)
    if len(chunks) > maximum_size:
        raise ValueError("trusted file is too large")
    return bytes(chunks)


def parse_release_manifest(
    path: Path, expected_uid: int, expected_gid: int, expected_mode: int = 0o444
) -> tuple[str, str, str, int, dict[str, tuple[int, int, str]]]:
    raw = _read_exact_regular(
        path, expected_uid, expected_gid, expected_mode, 8 * 1024 * 1024
    )
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise ValueError("release manifest encoding is invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("release manifest must be ASCII") from error
    if len(lines) < 6 or lines[0] != MANIFEST_HEADER:
        raise ValueError("release manifest header is invalid")
    metadata: dict[str, str] = {}
    for key, line in zip(("tag", "revision", "tree", "epoch"), lines[1:5]):
        prefix = f"{key} "
        if not line.startswith(prefix) or line == prefix:
            raise ValueError("release manifest metadata is invalid")
        metadata[key] = line[len(prefix) :]
    tag = metadata["tag"]
    revision = metadata["revision"]
    tree = metadata["tree"]
    epoch_text = metadata["epoch"]
    if RELEASE_TAG_RE.fullmatch(tag) is None or tag.startswith("-"):
        raise ValueError("release manifest tag is invalid")
    if GIT_REVISION_RE.fullmatch(revision) is None:
        raise ValueError("release manifest revision is invalid")
    if GIT_REVISION_RE.fullmatch(tree) is None:
        raise ValueError("release manifest tree is invalid")
    if not epoch_text.isdecimal():
        raise ValueError("release manifest epoch is invalid")

    entries: dict[str, tuple[int, int, str]] = {}
    previous_path = ""
    for line in lines[5:]:
        fields = line.split(" ", 3)
        if len(fields) != 4:
            raise ValueError("release manifest entry is invalid")
        git_mode_text, size_text, digest, relative = fields
        if git_mode_text not in ("100644", "100755"):
            raise ValueError("release contains a symlink, submodule, or special mode")
        if not size_text.isdecimal() or SHA256_RE.fullmatch(digest) is None:
            raise ValueError("release manifest size or digest is invalid")
        if (
            MANIFEST_PATH_RE.fullmatch(relative) is None
            or relative.startswith("/")
            or relative.endswith("/")
            or "//" in relative
            or any(part in ("", ".", "..", ".git") for part in relative.split("/"))
        ):
            raise ValueError("release manifest path is unsafe")
        if relative <= previous_path or relative in entries:
            raise ValueError("release manifest paths must be unique and sorted")
        for existing in entries:
            if relative.startswith(existing + "/") or existing.startswith(relative + "/"):
                raise ValueError("release manifest has a file/directory collision")
        previous_path = relative
        entries[relative] = (int(git_mode_text, 8), int(size_text), digest)
    if not entries:
        raise ValueError("release manifest has no files")
    return tag, revision, tree, int(epoch_text), entries


def _open_private_staged_file(
    root_descriptor: int,
    relative: str,
    expected_uid: int,
    expected_gid: int,
) -> tuple[int, os.stat_result]:
    directory_descriptor = os.dup(root_descriptor)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child_descriptor = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
            metadata = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PermissionError("staged path ancestor is not private")
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise PermissionError("staged release file is not a private regular file")
        return descriptor, metadata
    finally:
        os.close(directory_descriptor)


def seal_release(
    staging_root: Path,
    staging_manifest: Path,
    destination_root: Path,
    destination_manifest: Path,
    expected_tag: str,
    expected_revision: str,
    expected_tree: str,
    expected_epoch: int,
    operator_uid: int,
    operator_gid: int,
) -> None:
    """Copy a manifest-exact unprivileged export into an immutable root release."""
    staging_root = Path(staging_root)
    destination_root = Path(destination_root)
    destination_manifest = Path(destination_manifest)
    if (
        not staging_root.is_absolute()
        or staging_root.resolve(strict=True) != staging_root
        or not destination_root.is_absolute()
        or destination_root.parent.resolve(strict=True) != destination_root.parent
        or destination_manifest.parent != destination_root.parent
        or os.path.lexists(destination_root)
        or os.path.lexists(destination_manifest)
    ):
        raise ValueError("release sealing paths are unsafe or already exist")
    assert_private_directory(staging_root, operator_uid, operator_gid)
    tag, revision, tree, epoch, entries = parse_release_manifest(
        staging_manifest, operator_uid, operator_gid, 0o400
    )
    if (
        not hmac.compare_digest(tag, expected_tag)
        or not hmac.compare_digest(revision, expected_revision)
        or not hmac.compare_digest(tree, expected_tree)
        or epoch != expected_epoch
    ):
        raise RuntimeError("staged manifest does not match verified release metadata")

    expected_directories: set[str] = set()
    for relative in entries:
        parts = relative.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    stack = [(staging_root, "")]
    while stack:
        directory, prefix = stack.pop()
        with os.scandir(directory) as children:
            for child in children:
                relative = f"{prefix}/{child.name}" if prefix else child.name
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("staged release contains a symlink")
                if metadata.st_uid != operator_uid or metadata.st_gid != operator_gid:
                    raise PermissionError("staged release ownership is invalid")
                if stat.S_ISDIR(metadata.st_mode):
                    if stat.S_IMODE(metadata.st_mode) != 0o700:
                        raise PermissionError("staged release directory must be 0700")
                    observed_directories.add(relative)
                    stack.append((Path(child.path), relative))
                elif stat.S_ISREG(metadata.st_mode):
                    if stat.S_IMODE(metadata.st_mode) != 0o600:
                        raise PermissionError("staged release file must be 0600")
                    observed_files.add(relative)
                else:
                    raise ValueError("staged release contains a special file")
    if observed_files != set(entries) or observed_directories != expected_directories:
        raise RuntimeError("staged release has missing or unexpected paths")

    staging_descriptor = os.open(
        staging_root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    staging_opened = os.fstat(staging_descriptor)
    staging_before = os.lstat(staging_root)
    if (
        (staging_opened.st_dev, staging_opened.st_ino)
        != (staging_before.st_dev, staging_before.st_ino)
        or staging_opened.st_uid != operator_uid
        or staging_opened.st_gid != operator_gid
        or stat.S_IMODE(staging_opened.st_mode) != 0o700
    ):
        os.close(staging_descriptor)
        raise RuntimeError("staging root changed while opening")
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".release.", dir=destination_root.parent)
    )
    temporary_manifest_fd = -1
    temporary_manifest = destination_manifest.parent / (
        f".{destination_manifest.name}.{os.getpid()}"
    )
    try:
        os.chown(temporary_root, 0, 0)
        os.chmod(temporary_root, 0o700)
        for relative in sorted(expected_directories, key=lambda item: (item.count("/"), item)):
            directory = temporary_root / relative
            directory.mkdir(mode=0o700)
            os.chown(directory, 0, 0)
        for relative, (git_mode, expected_size, expected_digest) in entries.items():
            descriptor, opened = _open_private_staged_file(
                staging_descriptor, relative, operator_uid, operator_gid
            )
            target = temporary_root / relative
            target_descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            digest = hashlib.sha256()
            total = 0
            try:
                while total <= expected_size:
                    chunk = os.read(
                        descriptor, min(1024 * 1024, expected_size + 1 - total)
                    )
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(target_descriptor, view) :]
                after = os.fstat(descriptor)
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                ):
                    raise RuntimeError("staged file changed while copying")
                if total != expected_size or not hmac.compare_digest(
                    digest.hexdigest(), expected_digest
                ):
                    raise RuntimeError("staged file differs from signed raw blob")
                os.fchown(target_descriptor, 0, 0)
                os.fchmod(target_descriptor, 0o555 if git_mode == 0o100755 else 0o444)
                os.fsync(target_descriptor)
            finally:
                os.close(descriptor)
                os.close(target_descriptor)
        for relative in sorted(
            expected_directories, key=lambda item: (-item.count("/"), item)
        ):
            os.chmod(temporary_root / relative, 0o555)
        os.chmod(temporary_root, 0o555)

        manifest_raw = _read_exact_regular(
            staging_manifest, operator_uid, operator_gid, 0o400, 8 * 1024 * 1024
        )
        temporary_manifest_fd = os.open(
            temporary_manifest,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(manifest_raw)
        while view:
            view = view[os.write(temporary_manifest_fd, view) :]
        os.fchown(temporary_manifest_fd, 0, 0)
        os.fchmod(temporary_manifest_fd, 0o444)
        os.fsync(temporary_manifest_fd)
        os.close(temporary_manifest_fd)
        temporary_manifest_fd = -1
        os.replace(temporary_manifest, destination_manifest)
        os.replace(temporary_root, destination_root)
        parent_descriptor = os.open(
            destination_root.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        verify_release_filesystem(
            destination_root,
            destination_manifest,
            expected_tag,
            expected_revision,
            0,
            0,
        )
    except BaseException:
        if temporary_manifest_fd >= 0:
            os.close(temporary_manifest_fd)
        if os.path.lexists(temporary_manifest) and not temporary_manifest.is_symlink():
            temporary_manifest.unlink()
        # The private temporary is retained on failure if nonempty for forensic review.
        raise
    finally:
        os.close(staging_descriptor)


def verify_release_filesystem(
    release_root: Path,
    manifest_path: Path,
    expected_tag: str,
    expected_revision: str,
    expected_uid: int,
    expected_gid: int,
) -> int:
    release_root = Path(release_root)
    if (
        not release_root.is_absolute()
        or release_root.resolve(strict=True) != release_root
    ):
        raise ValueError("release root must be an existing canonical path")
    root_metadata = os.lstat(release_root)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("release root must be a regular directory")
    if (
        root_metadata.st_uid != expected_uid
        or root_metadata.st_gid != expected_gid
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
    ):
        raise PermissionError("release root must be immutable and trust-owned")
    tag, revision, _, epoch, entries = parse_release_manifest(
        manifest_path, expected_uid, expected_gid
    )
    if not hmac.compare_digest(tag, expected_tag):
        raise RuntimeError("release manifest tag does not match the recorded tag")
    if not hmac.compare_digest(revision, expected_revision):
        raise RuntimeError("release manifest revision does not match the recorded revision")

    expected_directories: set[str] = set()
    for relative in entries:
        parts = relative.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    stack = [(release_root, "")]
    while stack:
        directory, prefix = stack.pop()
        with os.scandir(directory) as children:
            for child in children:
                relative = f"{prefix}/{child.name}" if prefix else child.name
                child_metadata = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(child_metadata.st_mode):
                    raise ValueError("release filesystem contains a symlink")
                if stat.S_ISDIR(child_metadata.st_mode):
                    if (
                        child_metadata.st_uid != expected_uid
                        or child_metadata.st_gid != expected_gid
                        or stat.S_IMODE(child_metadata.st_mode) != 0o555
                    ):
                        raise PermissionError("release directory is not immutable")
                    observed_directories.add(relative)
                    stack.append((Path(child.path), relative))
                elif stat.S_ISREG(child_metadata.st_mode):
                    observed_files.add(relative)
                else:
                    raise ValueError("release filesystem contains a special file")
    if observed_files != set(entries) or observed_directories != expected_directories:
        raise RuntimeError("release filesystem has missing or unexpected paths")

    for relative, (git_mode, expected_size, expected_digest) in entries.items():
        path = release_root / relative
        required_mode = 0o555 if git_mode == 0o100755 else 0o444
        raw = _read_exact_regular(
            path, expected_uid, expected_gid, required_mode, expected_size
        )
        if len(raw) != expected_size:
            raise RuntimeError("release file size does not match manifest")
        actual_digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise RuntimeError("release file digest does not match manifest")
    return epoch


def restore_preflight(
    release_root: Path,
    release_manifest: Path,
    release_tag: str,
    expected_revision: str,
    snapshot: Path,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
    env_path: Path | None = None,
    operator_uid: int | None = None,
    operator_gid: int | None = None,
    release_uid: int = 0,
    release_gid: int = 0,
) -> None:
    if GIT_REVISION_RE.fullmatch(expected_revision) is None:
        raise ValueError("expected Git revision must be a full lowercase object ID")
    if operator_uid is None or operator_gid is None:
        operator_uid = release_uid
        operator_gid = release_gid
    release_epoch = verify_release_filesystem(
        release_root,
        release_manifest,
        release_tag,
        expected_revision,
        release_uid,
        release_gid,
    )
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
        RESTORE_RELEASE,
        RESTORE_RELEASE_MANIFEST,
        release_tag,
        expected_revision,
        RESTORE_DB,
        expected_sha256,
        OPSWARDEN_UID,
        OPSWARDEN_GID,
        Path(env_path),
        int(operator_uid),
        int(operator_gid),
        0,
        0,
    )
    print("restore preflight: exact revision, checksum, and integrity verified")


def seal_release_command(
    release_tag: str,
    expected_revision: str,
    expected_tree: str,
    expected_epoch: str,
    operator_uid: str,
    operator_gid: str,
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("release sealing must run as root")
    if (
        GIT_REVISION_RE.fullmatch(expected_revision) is None
        or GIT_REVISION_RE.fullmatch(expected_tree) is None
        or not expected_epoch.isdecimal()
        or not operator_uid.isdecimal()
        or not operator_gid.isdecimal()
    ):
        raise ValueError("release sealing metadata is invalid")
    if int(operator_uid) == 0:
        raise PermissionError("release staging owner must be non-root")
    seal_release(
        RESTORE_STAGING,
        RESTORE_STAGING_MANIFEST,
        RESTORE_RELEASE,
        RESTORE_RELEASE_MANIFEST,
        release_tag,
        expected_revision,
        expected_tree,
        int(expected_epoch),
        int(operator_uid),
        int(operator_gid),
    )
    print("sealed release: raw manifest and immutable filesystem verified")


def main(argv: list[str]) -> int:
    try:
        verify_trusted_helper(Path(__file__), TRUSTED_OPS_HELPER)
        if argv == ["snapshot"]:
            snapshot_command()
        elif len(argv) == 7 and argv[0] == "restore-preflight":
            restore_preflight_command(
                argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]
            )
        elif len(argv) == 7 and argv[0] == "seal-release":
            seal_release_command(
                argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]
            )
        else:
            raise ValueError(
                "usage: offline_ops.py snapshot | "
                "seal-release RELEASE_TAG EXPECTED_REVISION EXPECTED_TREE "
                "EXPECTED_EPOCH OPERATOR_UID OPERATOR_GID | "
                "restore-preflight RELEASE_TAG EXPECTED_REVISION RECORDED_SHA256 "
                "ENV_FILE OPERATOR_UID OPERATOR_GID"
            )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"offline operation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
