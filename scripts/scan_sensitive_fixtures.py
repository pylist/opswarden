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
MAX_ARCHIVE_EXPANDED_BYTES = 128 << 20
MAX_ARCHIVE_MEMBERS = 2048
MAX_FILES = 8192
MAX_DEPTH = 32
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
DIRECTORY_FLAGS = OPEN_FLAGS | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = OPEN_FLAGS | getattr(os, "O_NOFOLLOW", 0)


class ScanRefused(RuntimeError):
    pass


class ArchiveBudget:
    def __init__(self) -> None:
        self.members = 0
        self.expanded = 0

    def member(self) -> None:
        self.members += 1
        if self.members > MAX_ARCHIVE_MEMBERS:
            raise ScanRefused("recursive archive member count exceeds scan bound")

    def expand(self, size: int) -> None:
        self.expanded += size
        if self.expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ScanRefused("recursive archive expanded bytes exceed scan bound")


def _components(path: Path) -> tuple[str, ...]:
    if not path.is_absolute():
        raise ScanRefused("pinned path must be absolute")
    parts = path.parts[1:]
    if not parts or len(parts) > MAX_DEPTH or any(
        part in ("", ".", "..") or "/" in part or "\0" in part for part in parts
    ):
        raise ScanRefused("pinned path has unsafe components")
    return parts


def open_absolute(path: Path, *, directory: bool) -> int:
    current = os.open("/", DIRECTORY_FLAGS)
    try:
        parts = _components(path)
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = DIRECTORY_FLAGS if not final or directory else FILE_FLAGS
            following = os.open(part, flags, dir_fd=current)
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                raise ScanRefused("pinned path changed while opening")
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def open_relative(root_fd: int, relative: str, *, directory: bool = False) -> int:
    parts = tuple(relative.split("/"))
    if (
        not parts
        or len(parts) > MAX_DEPTH
        or any(part in ("", ".", "..") or "/" in part or "\0" in part for part in parts)
    ):
        raise ScanRefused("scan target has unsafe components")
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = DIRECTORY_FLAGS if not final or directory else FILE_FLAGS
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            following = os.open(part, flags, dir_fd=current)
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                raise ScanRefused("scan target changed while opening")
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def pinned_directory(value: str, label: str) -> tuple[Path, int]:
    path = Path(value)
    descriptor = open_absolute(path, directory=True)
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
        or path.resolve(strict=True) != path
    ):
        os.close(descriptor)
        raise ScanRefused(f"{label} must be a canonical non-symlink directory")
    return path, descriptor


def verify_pinned_directory(path: Path, descriptor: int) -> None:
    current = open_absolute(path, directory=True)
    try:
        if identity(os.fstat(current)) != identity(os.fstat(descriptor)):
            raise ScanRefused("pinned root namespace changed during scan")
    finally:
        os.close(current)


def private_pattern_file(
    runtime_fd: int, runtime_path: Path, value: str
) -> tuple[bytes, ...]:
    expected = runtime_path / "sensitive-patterns"
    if value != str(expected):
        raise ScanRefused("protected value file is outside the pinned runtime")
    descriptor = open_relative(runtime_fd, "sensitive-patterns")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > (1 << 20)
        ):
            raise ScanRefused("protected value file ownership, mode, or type is unsafe")
        encoded = read_bounded(descriptor, (1 << 20))
        after = os.fstat(descriptor)
        if identity(before) != identity(after) or len(encoded) != before.st_size:
            raise ScanRefused("protected value file changed while reading")
        namespace = os.stat(
            "sensitive-patterns", dir_fd=runtime_fd, follow_symlinks=False
        )
        if identity(namespace) != identity(before):
            raise ScanRefused("protected value path changed while reading")
    finally:
        os.close(descriptor)
    patterns = tuple(line for line in encoded.splitlines() if line)
    if len(patterns) < 12 or len(patterns) > 128:
        raise ScanRefused("protected value pattern count is outside the expected bound")
    if any(len(pattern) < 12 or len(pattern) > 4096 for pattern in patterns):
        raise ScanRefused("protected value pattern length is unsafe")
    if len(set(patterns)) != len(patterns):
        raise ScanRefused("protected value patterns must be unique")
    return patterns


def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1 << 20, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ScanRefused("scan target exceeds size bound")


def scan_descriptor(
    descriptor: int,
    name: str,
    patterns: tuple[bytes, ...],
    budget: ArchiveBudget,
    expected: os.stat_result | None = None,
) -> bool:
    before = os.fstat(descriptor)
    if expected is not None and identity(expected) != identity(before):
        raise ScanRefused("scan target changed while opening")
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size > MAX_FILE_BYTES
    ):
        raise ScanRefused("scan target is not a safe bounded regular file")
    encoded = read_bounded(descriptor, MAX_FILE_BYTES)
    after = os.fstat(descriptor)
    if identity(before) != identity(after) or len(encoded) != before.st_size:
        raise ScanRefused("scan target changed while reading")
    return contains_pattern(encoded, patterns) or scan_archive(
        encoded, name.rsplit("/", 1)[-1], patterns, budget=budget
    )


def scan_tree(
    root_fd: int,
    patterns: tuple[bytes, ...],
    budget: ArchiveBudget,
) -> tuple[bool, int]:
    file_count = 0
    leaked = False

    def visit(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal file_count, leaked
        if depth > MAX_DEPTH:
            raise ScanRefused("artifact tree depth exceeds scan bound")
        names = os.listdir(directory_fd)
        for name in names:
            if name in ("", ".", "..") or "/" in name or "\0" in name:
                raise ScanRefused("artifact tree contains an unsafe name")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise ScanRefused("artifact directory ownership or mode is unsafe")
                child = os.open(name, DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child)
                    if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ScanRefused("artifact directory changed while opening")
                    visit(child, relative, depth + 1)
                    after = os.fstat(child)
                    namespace = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        identity(opened) != identity(after)
                        or identity(opened) != identity(namespace)
                    ):
                        raise ScanRefused("artifact directory changed while scanning")
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or metadata.st_size > MAX_FILE_BYTES
                ):
                    raise ScanRefused("artifact file exceeds scan size bound")
                descriptor = os.open(name, FILE_FLAGS, dir_fd=directory_fd)
                try:
                    file_count += 1
                    if file_count > MAX_FILES:
                        raise ScanRefused("artifact file count exceeds scan bound")
                    if scan_descriptor(
                        descriptor, relative, patterns, budget, expected=metadata
                    ):
                        leaked = True
                    namespace = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if identity(namespace) != identity(metadata):
                        raise ScanRefused("artifact file namespace changed while scanning")
                finally:
                    os.close(descriptor)
                if file_count > MAX_FILES:
                    raise ScanRefused("artifact file count exceeds scan bound")
            else:
                raise ScanRefused("artifact tree contains a symlink or special file")

    visit(root_fd, "", 0)
    return leaked, file_count


def pin_and_scan_top_entry(
    parent_fd: int,
    name: str,
    patterns: tuple[bytes, ...],
    budget: ArchiveBudget,
) -> tuple[bool, int, int, os.stat_result]:
    if name in ("", ".", "..") or "/" in name or "\0" in name:
        raise ScanRefused("top-level artifact root name is unsafe")
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if identity(before) != identity(opened):
            raise ScanRefused("top-level artifact root changed while opening")
        result = scan_tree(descriptor, patterns, budget)
        after = os.fstat(descriptor)
        namespace = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if identity(opened) != identity(after) or identity(opened) != identity(namespace):
            raise ScanRefused("top-level artifact root changed while scanning")
        return result[0], result[1], descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def revalidate_top_entry(
    parent_fd: int,
    name: str,
    descriptor: int,
    baseline: os.stat_result,
) -> None:
    opened = os.fstat(descriptor)
    namespace = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(baseline) != identity(opened) or identity(baseline) != identity(namespace):
        raise ScanRefused("top-level artifact root changed after its scan")


def scan_top_entry(
    parent_fd: int,
    name: str,
    patterns: tuple[bytes, ...],
    budget: ArchiveBudget,
) -> tuple[bool, int]:
    leaked, count, descriptor, baseline = pin_and_scan_top_entry(
        parent_fd, name, patterns, budget
    )
    try:
        revalidate_top_entry(parent_fd, name, descriptor, baseline)
        return leaked, count
    finally:
        os.close(descriptor)


def contains_pattern(encoded: bytes, patterns: tuple[bytes, ...]) -> bool:
    return any(pattern in encoded for pattern in patterns)


def _archive_body(handle, declared: int, budget: ArchiveBudget) -> bytes:
    if declared < 0 or declared > MAX_ARCHIVE_MEMBER_BYTES:
        raise ScanRefused("archive member exceeds scan size bound")
    body = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if len(body) > MAX_ARCHIVE_MEMBER_BYTES or len(body) != declared:
        raise ScanRefused("archive member length is unsafe")
    budget.expand(len(body))
    return body


def scan_archive(
    encoded: bytes,
    name: str,
    patterns: tuple[bytes, ...],
    depth: int = 0,
    budget: ArchiveBudget | None = None,
) -> bool:
    if depth > 3:
        raise ScanRefused("nested archive depth exceeds scan bound")
    budget = ArchiveBudget() if budget is None else budget
    lowered = name.lower()
    if lowered.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            for member in archive.infolist():
                budget.member()
                if member.is_dir():
                    continue
                with archive.open(member, "r") as handle:
                    body = _archive_body(handle, member.file_size, budget)
                if contains_pattern(body, patterns) or scan_archive(
                    body, member.filename, patterns, depth + 1, budget
                ):
                    return True
    elif lowered.endswith((".tar", ".tar.gz", ".tgz")):
        mode = "r:gz" if lowered.endswith((".tar.gz", ".tgz")) else "r:"
        with tarfile.open(fileobj=io.BytesIO(encoded), mode=mode) as archive:
            for member in archive:
                budget.member()
                if member.issym() or member.islnk():
                    raise ScanRefused("archive contains a link")
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    raise ScanRefused("archive member cannot be read")
                body = _archive_body(handle, member.size, budget)
                if contains_pattern(body, patterns) or scan_archive(
                    body, member.name, patterns, depth + 1, budget
                ):
                    return True
    elif lowered.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as archive:
            body = archive.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
        if len(body) > MAX_ARCHIVE_MEMBER_BYTES:
            raise ScanRefused("compressed artifact exceeds scan size bound")
        budget.member()
        budget.expand(len(body))
        return contains_pattern(body, patterns) or scan_archive(
            body, lowered[:-3], patterns, depth + 1, budget
        )
    return False


def scan_file(
    root_fd: int,
    relative: str,
    patterns: tuple[bytes, ...],
    budget: ArchiveBudget | None = None,
) -> bool:
    budget = ArchiveBudget() if budget is None else budget
    descriptor = open_relative(root_fd, relative)
    try:
        before = os.fstat(descriptor)
        leaked = scan_descriptor(descriptor, relative, patterns, budget)
        namespace = open_relative(root_fd, relative)
        try:
            if identity(os.fstat(namespace)) != identity(before):
                raise ScanRefused("scan target path changed while reading")
        finally:
            os.close(namespace)
    finally:
        os.close(descriptor)
    return leaked


def tracked_files(repo_root: Path) -> list[str]:
    completed = subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "-C", str(repo_root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env={
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
    )
    paths = [item.decode("utf-8", errors="strict") for item in completed.stdout.split(b"\0") if item]
    if len(paths) > MAX_FILES:
        raise ScanRefused("tracked scan target count exceeds bound")
    return paths


def main() -> int:
    descriptors: list[int] = []
    try:
        repo_root, repo_fd = pinned_directory(
            os.environ.get("OPSWARDEN_E2E_REPO_ROOT", ""), "repository root"
        )
        artifact_dir, artifact_fd = pinned_directory(
            os.environ.get("OPSWARDEN_E2E_ARTIFACT_DIR", ""), "artifact root"
        )
        runtime_dir, runtime_fd = pinned_directory(
            os.environ.get("OPSWARDEN_E2E_RUNTIME_DIR", ""), "runtime root"
        )
        descriptors.extend((repo_fd, artifact_fd, runtime_fd))
        patterns = private_pattern_file(
            runtime_fd,
            runtime_dir,
            os.environ.get("OPSWARDEN_E2E_SECRET_FILE", ""),
        )
        budget = ArchiveBudget()

        required = (
            (runtime_fd, "data/opswarden.db"),
            (artifact_fd, "backups/online-backup.sqlite3"),
            (artifact_fd, "logs/application.log"),
            (artifact_fd, "logs/restore-compose.log"),
            (artifact_fd, "audit/audit-export.json"),
            (artifact_fd, "browser/browser-storage.json"),
            (artifact_fd, "errors/captured-errors.json"),
        )
        for root_fd, relative in required:
            descriptor = open_relative(root_fd, relative)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ScanRefused("a required artifact class is unsafe")
            finally:
                os.close(descriptor)

        roots = (
            (runtime_fd, "data"),
            (runtime_fd, "backups"),
            (artifact_fd, "backups"),
            (artifact_fd, "logs"),
            (artifact_fd, "audit"),
            (artifact_fd, "browser"),
            (artifact_fd, "errors"),
            (artifact_fd, "playwright"),
        )
        leaked = False
        scanned_files = 0
        retained_tops: list[tuple[int, str, int, os.stat_result]] = []
        for root_fd, relative in roots:
            tree_leaked, tree_count, top_fd, baseline = pin_and_scan_top_entry(
                root_fd, relative, patterns, budget
            )
            retained_tops.append((root_fd, relative, top_fd, baseline))
            descriptors.append(top_fd)
            leaked = leaked or tree_leaked
            scanned_files += tree_count
            if scanned_files > MAX_FILES:
                raise ScanRefused("aggregate artifact file count exceeds scan bound")
        for relative in tracked_files(repo_root):
            scanned_files += 1
            if scanned_files > MAX_FILES:
                raise ScanRefused("aggregate scan target count exceeds bound")
            leaked = scan_file(repo_fd, relative, patterns, budget) or leaked
        for parent_fd, name, top_fd, baseline in retained_tops:
            revalidate_top_entry(parent_fd, name, top_fd, baseline)
        verify_pinned_directory(repo_root, repo_fd)
        verify_pinned_directory(artifact_dir, artifact_fd)
        verify_pinned_directory(runtime_dir, runtime_fd)
        if leaked:
            print(
                "sensitive fixture scan failed: a protected value escaped an encrypted boundary",
                file=sys.stderr,
            )
            return 1
        print(f"sensitive fixture scan: clean ({len(roots)} artifact classes)")
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
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
