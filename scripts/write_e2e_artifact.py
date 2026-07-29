#!/usr/bin/env python3
"""Append a bounded raw MCP body through pinned, no-follow descriptors."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
MAX_BODY = 4 << 20


def open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise RuntimeError("artifact root must be absolute")
    current = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in ("", ".", "..") or "/" in component or "\0" in component:
                raise RuntimeError("artifact root component is unsafe")
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            following = os.open(component, DIRECTORY_FLAGS, dir_fd=current)
            opened = os.fstat(following)
            if (
                not stat.S_ISDIR(before.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                os.close(following)
                raise RuntimeError("artifact root changed or linked while opening")
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] != "errors/mcp-failures.bin":
        raise RuntimeError("writer target is outside the exact artifact allowlist")
    artifact = Path(argv[0])
    root_fd = open_absolute_directory(artifact)
    errors_fd = -1
    output_fd = -1
    try:
        root = os.fstat(root_fd)
        if root.st_uid != os.getuid() or stat.S_IMODE(root.st_mode) != 0o700:
            raise RuntimeError("artifact root ownership or mode is unsafe")
        errors_before = os.stat("errors", dir_fd=root_fd, follow_symlinks=False)
        errors_fd = os.open("errors", DIRECTORY_FLAGS, dir_fd=root_fd)
        errors_opened = os.fstat(errors_fd)
        if (
            identity(errors_before) != identity(errors_opened)
            or not stat.S_ISDIR(errors_opened.st_mode)
            or errors_opened.st_uid != os.getuid()
            or stat.S_IMODE(errors_opened.st_mode) != 0o700
        ):
            raise RuntimeError("artifact errors directory is unsafe")
        output_fd = os.open(
            "mcp-failures.bin",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=errors_fd,
        )
        output = os.fstat(output_fd)
        namespace = os.stat(
            "mcp-failures.bin", dir_fd=errors_fd, follow_symlinks=False
        )
        if (
            identity(output) != identity(namespace)
            or not stat.S_ISREG(output.st_mode)
            or output.st_uid != os.getuid()
            or stat.S_IMODE(output.st_mode) != 0o600
        ):
            raise RuntimeError("MCP failure artifact is unsafe")
        body = sys.stdin.buffer.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise RuntimeError("MCP failure body exceeds bound")
        record = len(body).to_bytes(8, "big") + body
        offset = 0
        while offset < len(record):
            offset += os.write(output_fd, record[offset:])
        os.fsync(output_fd)
        after = os.fstat(output_fd)
        namespace_after = os.stat(
            "mcp-failures.bin", dir_fd=errors_fd, follow_symlinks=False
        )
        errors_after = os.stat("errors", dir_fd=root_fd, follow_symlinks=False)
        if (
            identity(after) != identity(namespace_after)
            or identity(errors_after) != identity(errors_opened)
        ):
            raise RuntimeError("artifact namespace changed while writing")
        return 0
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        if errors_fd >= 0:
            os.close(errors_fd)
        os.close(root_fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError) as error:
        print(f"protected artifact write refused: {error}", file=sys.stderr)
        raise SystemExit(2)
