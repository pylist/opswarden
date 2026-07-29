#!/usr/bin/env python3
"""Hermetically bind a signed Git tag to a raw-object release export."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable


REPOSITORY = Path("/opt/opswarden")
STAGING_ROOT = Path("/srv/opswarden-restore-staging/release")
TRUSTED_EXPORTER = Path("/usr/local/libexec/opswarden/release_export.py")
GIT = "/usr/bin/git"
GNUPG_HOME = "/etc/opswarden/release-gnupg"
MANIFEST_HEADER = "OPSWARDEN-RELEASE-MANIFEST-V2"
OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,254}")
PATH_RE = re.compile(r"[A-Za-z0-9._+@/-]{1,4096}")
MAX_ENTRIES = 20_000
MAX_DEPTH = 32
MAX_BLOB_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024


def verify_trust_anchor(path: Path = Path(__file__)) -> None:
    expected = TRUSTED_EXPORTER
    if path != expected or path.resolve(strict=True) != expected:
        raise PermissionError("exporter is not executing from its fixed trust anchor")
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise PermissionError("trusted exporter metadata is invalid")


class RawGit:
    def __init__(self, repository: Path, git_binary: str = GIT):
        self.repository = Path(repository)
        self.git_binary = git_binary
        self.environment = {
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GNUPGHOME": GNUPG_HOME,
        }
        self.prefix = [
            self.git_binary,
            "--no-replace-objects",
            "-c",
            f"safe.directory={self.repository}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "gpg.format=openpgp",
            "-c",
            "gpg.program=/usr/bin/gpg",
            "-c",
            "gpg.minTrustLevel=fully",
            "-C",
            str(self.repository),
        ]

    def run(self, *arguments: str, input_bytes: bytes | None = None) -> bytes:
        return subprocess.run(
            [*self.prefix, *arguments],
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
        ).stdout

    def exact_line(self, *arguments: str) -> str:
        raw = self.run(*arguments)
        if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
            raise RuntimeError("Git did not return one exact line")
        return raw[:-1].decode("ascii")

    def object_format(self) -> tuple[str, int]:
        value = self.exact_line("rev-parse", "--show-object-format")
        if value == "sha1":
            return value, 20
        if value == "sha256":
            return value, 32
        raise RuntimeError("unsupported Git object format")

    def read_object(self, oid: str, object_format: str) -> tuple[str, bytes]:
        if OID_RE.fullmatch(oid) is None:
            raise ValueError("invalid object ID")
        output = self.run("cat-file", "--batch", input_bytes=(oid + "\n").encode("ascii"))
        header, separator, remainder = output.partition(b"\n")
        if not separator:
            raise RuntimeError("invalid cat-file batch output")
        fields = header.split(b" ")
        if len(fields) != 3 or fields[0] != oid.encode("ascii"):
            raise RuntimeError("cat-file returned a different object")
        object_type = fields[1].decode("ascii")
        if not fields[2].isdigit():
            raise RuntimeError("cat-file returned an invalid size")
        size = int(fields[2])
        if len(remainder) != size + 1 or remainder[-1:] != b"\n":
            raise RuntimeError("cat-file returned truncated or extra bytes")
        raw = remainder[:-1]
        digest = hashlib.sha1() if object_format == "sha1" else hashlib.sha256()
        digest.update(object_type.encode("ascii") + b" " + str(size).encode("ascii") + b"\0")
        digest.update(raw)
        if digest.hexdigest() != oid:
            raise RuntimeError("raw Git object does not match its object ID")
        return object_type, raw

    def verify_tag(self, tag_oid: str) -> None:
        result = subprocess.run(
            [*self.prefix, "verify-tag", "--raw", tag_oid],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=self.environment,
        )
        if result.returncode != 0:
            raise RuntimeError("release tag signature verification failed")


def _header_value(raw: bytes, key: bytes) -> bytes:
    prefix = key + b" "
    values = [
        line[len(prefix) :]
        for line in raw.split(b"\n\n", 1)[0].splitlines()
        if line.startswith(prefix)
    ]
    if len(values) != 1:
        raise RuntimeError("Git object header is missing or duplicated")
    return values[0]


def _safe_component(name: bytes) -> str:
    try:
        value = name.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("release paths must be ASCII") from error
    if (
        not value
        or value in (".", "..", ".git")
        or "/" in value
        or PATH_RE.fullmatch(value) is None
    ):
        raise ValueError("unsafe release path component")
    return value


def _write_staged_file(root: Path, relative: str, raw: bytes) -> None:
    path = root / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def export_release(
    repository: Path,
    staging_root: Path,
    release_tag: str,
    expected_revision: str,
    *,
    git_binary: str = GIT,
    signature_verifier: Callable[[RawGit, str], None] | None = None,
) -> bytes:
    if TAG_RE.fullmatch(release_tag) is None or release_tag.startswith("-"):
        raise ValueError("unsafe release tag")
    if OID_RE.fullmatch(expected_revision) is None:
        raise ValueError("expected revision must be a full object ID")
    staging_root = Path(staging_root)
    metadata = os.lstat(staging_root)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PermissionError("staging root must be a private directory")
    staging_descriptor = os.open(
        staging_root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(staging_descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RuntimeError("staging root changed while opening")
        if os.listdir(staging_descriptor):
            raise ValueError("staging root must be empty")
    finally:
        os.close(staging_descriptor)

    git = RawGit(repository, git_binary)
    object_format, oid_bytes = git.object_format()
    replace_refs = git.run("for-each-ref", "--format=%(refname)", "refs/replace/")
    if replace_refs:
        raise RuntimeError("repository contains replacement refs")
    tag_oid = git.exact_line("rev-parse", f"refs/tags/{release_tag}^{{tag}}")
    (signature_verifier or (lambda instance, oid: instance.verify_tag(oid)))(git, tag_oid)
    tag_type, tag_raw = git.read_object(tag_oid, object_format)
    if tag_type != "tag":
        raise RuntimeError("release reference is not an annotated tag")
    commit_oid = _header_value(tag_raw, b"object").decode("ascii")
    if _header_value(tag_raw, b"type") != b"commit":
        raise RuntimeError("signed tag does not target a commit")
    if _header_value(tag_raw, b"tag").decode("utf-8") != release_tag:
        raise RuntimeError("signed tag name does not match")
    if commit_oid != expected_revision:
        raise RuntimeError("signed tag commit does not match recorded revision")
    commit_type, commit_raw = git.read_object(commit_oid, object_format)
    if commit_type != "commit":
        raise RuntimeError("tag target is not a commit")
    tree_oid = _header_value(commit_raw, b"tree").decode("ascii")
    committer = _header_value(commit_raw, b"committer")
    match = re.search(rb" ([0-9]+) [+-][0-9]{4}$", committer)
    if match is None:
        raise RuntimeError("commit epoch is invalid")
    epoch = int(match.group(1))

    entries: list[tuple[str, str, str, int, str]] = []
    total_size = 0
    seen_paths: set[str] = set()

    def walk_tree(oid: str, prefix: str, depth: int) -> None:
        nonlocal total_size
        if depth > MAX_DEPTH:
            raise ValueError("release tree is too deep")
        object_type, raw = git.read_object(oid, object_format)
        if object_type != "tree":
            raise RuntimeError("tree entry does not reference a tree")
        cursor = 0
        parsed: list[tuple[bytes, bytes, str]] = []
        while cursor < len(raw):
            space = raw.find(b" ", cursor)
            nul = raw.find(b"\0", space + 1)
            if space < 0 or nul < 0 or nul + 1 + oid_bytes > len(raw):
                raise RuntimeError("malformed raw tree object")
            mode = raw[cursor:space]
            name = raw[space + 1 : nul]
            child_oid = raw[nul + 1 : nul + 1 + oid_bytes].hex()
            cursor = nul + 1 + oid_bytes
            parsed.append((mode, name, child_oid))
        canonical = sorted(
            parsed,
            key=lambda item: item[1] + (b"/" if item[0] == b"40000" else b""),
        )
        if parsed != canonical:
            raise RuntimeError("tree entries are not in canonical Git order")
        names = [item[1] for item in parsed]
        if len(names) != len(set(names)):
            raise ValueError("tree contains duplicate path components")
        for mode, name, child_oid in parsed:
            component = _safe_component(name)
            relative = f"{prefix}/{component}" if prefix else component
            if len(relative) > 4096 or relative in seen_paths:
                raise ValueError("duplicate or oversized release path")
            if mode == b"40000":
                walk_tree(child_oid, relative, depth + 1)
                continue
            if mode not in (b"100644", b"100755"):
                raise ValueError("release contains symlink, submodule, or special mode")
            child_type, blob = git.read_object(child_oid, object_format)
            if child_type != "blob":
                raise RuntimeError("file entry does not reference a blob")
            if len(blob) > MAX_BLOB_SIZE:
                raise ValueError("release blob exceeds size limit")
            total_size += len(blob)
            if total_size > MAX_TOTAL_SIZE or len(entries) >= MAX_ENTRIES:
                raise ValueError("release exceeds bounded export limits")
            seen_paths.add(relative)
            sha256 = hashlib.sha256(blob).hexdigest()
            _write_staged_file(staging_root, relative, blob)
            entries.append((mode.decode("ascii"), child_oid, relative, len(blob), sha256))

    walk_tree(tree_oid, "", 0)
    if not entries:
        raise ValueError("release contains no regular files")
    lines = [
        MANIFEST_HEADER,
        f"object-format {object_format}",
        f"tag-name {release_tag}",
        f"tag-oid {tag_oid}",
        f"commit-oid {commit_oid}",
        f"tree-oid {tree_oid}",
        f"epoch {epoch}",
    ]
    for mode, blob_oid, relative, size, sha256 in sorted(entries, key=lambda item: item[2]):
        lines.append(f"{mode} {blob_oid} {size} {sha256} {relative}")
    return ("\n".join(lines) + "\n").encode("ascii")


def main(argv: list[str]) -> int:
    try:
        verify_trust_anchor()
        if os.geteuid() == 0:
            raise PermissionError("release exporter must run unprivileged")
        if len(argv) != 2:
            raise ValueError("usage: release_export.py RELEASE_TAG EXPECTED_REVISION")
        manifest = export_release(REPOSITORY, STAGING_ROOT, argv[0], argv[1])
        sys.stdout.buffer.write(manifest)
        sys.stdout.buffer.flush()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"release export refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
