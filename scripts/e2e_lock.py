#!/usr/bin/env python3
"""Acquire an OS-released repository E2E lock and exec the runner."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise RuntimeError("usage: e2e_lock.py ABSOLUTE_LOCK ABSOLUTE_RUNNER")
    lock_path = Path(argv[0])
    runner = Path(argv[1])
    if (
        not lock_path.is_absolute()
        or lock_path.name != "opswarden-e2e.lock"
        or lock_path.parent.name != ".tmp"
        or not runner.is_absolute()
        or runner.name != "verify-e2e.sh"
    ):
        raise RuntimeError("lock or runner path is outside the fixed namespace")
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        raise RuntimeError("E2E lock file ownership or mode is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("E2E release gate refused: another run owns the OS lock", file=sys.stderr)
        return 75
    os.set_inheritable(descriptor, True)
    environment = dict(os.environ)
    environment["OPSWARDEN_E2E_LOCK_HELD"] = "1"
    os.execve("/bin/bash", ["/bin/bash", str(runner)], environment)
    return 70


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError) as error:
        print(f"E2E lock refused: {error}", file=sys.stderr)
        raise SystemExit(75)
