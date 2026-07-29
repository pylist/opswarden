#!/usr/bin/env python3
"""Remove only the exact E2E secret files through pinned, no-follow descriptors."""

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

ALLOWED = {
    "sensitive-patterns",
    "control.json",
    "master.key",
    "restore/master.key",
    "restore-wrong/master.key",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        fail("runtime directory must be absolute")
    components = path.parts[1:]
    if not components or any(
        component in ("", ".", "..") or "/" in component or "\0" in component
        for component in components
    ):
        fail("runtime directory components are unsafe")
    current = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in components:
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            following = os.open(component, DIRECTORY_FLAGS, dir_fd=current)
            opened = os.fstat(following)
            if (
                not stat.S_ISDIR(before.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                os.close(following)
                fail("runtime path changed or linked while opening")
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not Path(argv[0]).is_absolute():
        fail("usage: cleanup_e2e_secrets.py ABSOLUTE_RUNTIME RELATIVE_TARGET")
    relative = argv[1]
    if relative not in ALLOWED:
        fail("cleanup target is outside the exact allowlist")
    root = Path(argv[0])
    if root.parent.name != ".tmp" or not root.name.startswith("opswarden-e2e."):
        fail("runtime directory is outside the E2E namespace")
    root_fd = open_absolute_directory(root)
    try:
        root_metadata = os.fstat(root_fd)
        if (
            root_metadata.st_uid != os.getuid()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            fail("runtime directory ownership or mode is unsafe")
        current = os.dup(root_fd)
        try:
            parts = relative.split("/")
            for component in parts[:-1]:
                before = os.stat(component, dir_fd=current, follow_symlinks=False)
                following = os.open(component, DIRECTORY_FLAGS, dir_fd=current)
                opened = os.fstat(following)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    os.close(following)
                    fail("cleanup directory changed while opening")
                os.close(current)
                current = following
            name = parts[-1]
            try:
                metadata = os.stat(name, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return 0
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                fail("cleanup target is not a private owned regular file")
            os.unlink(name, dir_fd=current)
        finally:
            os.close(current)
    finally:
        os.close(root_fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError) as error:
        print(f"E2E secret cleanup refused: {error}", file=sys.stderr)
        raise SystemExit(2)
