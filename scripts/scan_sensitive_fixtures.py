#!/usr/bin/env python3
"""Fail closed when generated E2E secrets appear outside approved control files."""

from __future__ import annotations

import gzip
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import zipfile


MAX_FILE_BYTES = 64 << 20
MAX_ARCHIVE_MEMBER_BYTES = 32 << 20
MAX_ARCHIVE_MEMBERS = 2048


class ScanRefused(RuntimeError):
    pass


def canonical_directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ScanRefused(f"{label} must be absolute")
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ScanRefused(f"{label} is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ScanRefused(f"{label} must be a non-symlink directory")
    if path.resolve(strict=True) != path:
        raise ScanRefused(f"{label} must be canonical")
    return path


def private_pattern_file(value: str) -> tuple[Path, tuple[bytes, ...]]:
    path = Path(value)
    if not path.is_absolute():
        raise ScanRefused("protected value file must be absolute")
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > (1 << 20)
        or path.resolve(strict=True) != path
    ):
        raise ScanRefused("protected value file ownership, mode, or type is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ScanRefused("protected value file changed while opening")
        encoded = os.read(descriptor, (1 << 20) + 1)
    finally:
        os.close(descriptor)
    if len(encoded) != metadata.st_size:
        raise ScanRefused("protected value file changed while reading")
    patterns = tuple(line for line in encoded.splitlines() if line)
    if len(patterns) < 12 or len(patterns) > 128:
        raise ScanRefused("protected value pattern count is outside the expected bound")
    if any(len(pattern) < 12 or len(pattern) > 4096 for pattern in patterns):
        raise ScanRefused("protected value pattern length is unsafe")
    if len(set(patterns)) != len(patterns):
        raise ScanRefused("protected value patterns must be unique")
    return path, patterns


def regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ScanRefused("artifact tree contains a symlink or special directory")
            safe_directories.append(name)
        directories[:] = safe_directories
        for name in names:
            candidate = current_path / name
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ScanRefused("artifact tree contains a symlink or special file")
            if metadata.st_size > MAX_FILE_BYTES:
                raise ScanRefused("artifact file exceeds scan size bound")
            files.append(candidate)
            if len(files) > 8192:
                raise ScanRefused("artifact file count exceeds scan bound")
    return files


def contains_pattern(encoded: bytes, patterns: tuple[bytes, ...]) -> bool:
    return any(pattern in encoded for pattern in patterns)


def scan_archive(encoded: bytes, name: str, patterns: tuple[bytes, ...], depth: int = 0) -> bool:
    if depth > 3:
        raise ScanRefused("nested archive depth exceeds scan bound")
    lowered = name.lower()
    if lowered.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ScanRefused("archive member count exceeds scan bound")
            for member in members:
                if member.is_dir():
                    continue
                if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ScanRefused("archive member exceeds scan size bound")
                body = archive.read(member)
                if contains_pattern(body, patterns) or scan_archive(
                    body, member.filename, patterns, depth + 1
                ):
                    return True
    elif lowered.endswith((".tar", ".tar.gz", ".tgz")):
        mode = "r:gz" if lowered.endswith((".tar.gz", ".tgz")) else "r:"
        with tarfile.open(fileobj=io.BytesIO(encoded), mode=mode) as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ScanRefused("archive member count exceeds scan bound")
            for member in members:
                if member.issym() or member.islnk():
                    raise ScanRefused("archive contains a link")
                if not member.isfile():
                    continue
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ScanRefused("archive member exceeds scan size bound")
                handle = archive.extractfile(member)
                body = b"" if handle is None else handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if contains_pattern(body, patterns) or scan_archive(
                    body, member.name, patterns, depth + 1
                ):
                    return True
    elif lowered.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as archive:
            body = archive.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
        if len(body) > MAX_ARCHIVE_MEMBER_BYTES:
            raise ScanRefused("compressed artifact exceeds scan size bound")
        return contains_pattern(body, patterns) or scan_archive(
            body, lowered[:-3], patterns, depth + 1
        )
    return False


def scan_file(path: Path, patterns: tuple[bytes, ...]) -> bool:
    encoded = path.read_bytes()
    return contains_pattern(encoded, patterns) or scan_archive(
        encoded, path.name, patterns
    )


def tracked_files(repo_root: Path) -> list[Path]:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(repo_root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    paths = [
        repo_root / item.decode("utf-8", errors="strict")
        for item in completed.stdout.split(b"\0")
        if item
    ]
    for path in paths:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ScanRefused("tracked scan target is not a regular file")
        if metadata.st_size > MAX_FILE_BYTES:
            raise ScanRefused("tracked scan target exceeds size bound")
    return paths


def main() -> int:
    try:
        repo_root = canonical_directory(
            os.environ.get("OPSWARDEN_E2E_REPO_ROOT", ""), "repository root"
        )
        artifact_dir = canonical_directory(
            os.environ.get("OPSWARDEN_E2E_ARTIFACT_DIR", ""), "artifact root"
        )
        runtime_dir = canonical_directory(
            os.environ.get("OPSWARDEN_E2E_RUNTIME_DIR", ""), "runtime root"
        )
        pattern_path, patterns = private_pattern_file(
            os.environ.get("OPSWARDEN_E2E_SECRET_FILE", "")
        )

        required_files = [
            runtime_dir / "data" / "opswarden.db",
            artifact_dir / "backups" / "online-backup.sqlite3",
            artifact_dir / "logs" / "application.log",
            artifact_dir / "logs" / "restore-compose.log",
            artifact_dir / "audit" / "audit-export.json",
            artifact_dir / "browser" / "browser-storage.json",
            artifact_dir / "errors" / "captured-errors.json",
        ]
        scan_roots = [
            runtime_dir / "data",
            runtime_dir / "backups",
            artifact_dir / "backups",
            artifact_dir / "logs",
            artifact_dir / "audit",
            artifact_dir / "browser",
            artifact_dir / "errors",
            artifact_dir / "playwright",
        ]
        for path in required_files:
            if not path.is_file() or path.is_symlink():
                raise ScanRefused("a required artifact class is missing or unsafe")
        files: list[Path] = []
        for scan_root in scan_roots:
            canonical_directory(str(scan_root), "artifact class")
            files.extend(regular_files(scan_root))
        files.extend(tracked_files(repo_root))
        files = list(dict.fromkeys(files))
        if pattern_path in files:
            raise ScanRefused("protected value file entered the scan target set")
        if any(scan_file(path, patterns) for path in files):
            print(
                "sensitive fixture scan failed: a protected value escaped an encrypted boundary",
                file=sys.stderr,
            )
            return 1
        print(f"sensitive fixture scan: clean ({len(scan_roots)} artifact classes)")
        return 0
    except (
        OSError,
        ScanRefused,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"sensitive fixture scan refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
