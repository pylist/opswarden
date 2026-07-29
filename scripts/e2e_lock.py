#!/usr/bin/env python3
"""Hold an unforgeable OS lock while supervising the complete E2E gate."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise RuntimeError("repository root must be absolute")
    components = path.parts[1:]
    if not components or any(
        component in ("", ".", "..") or "/" in component or "\0" in component
        for component in components
    ):
        raise RuntimeError("repository root components are unsafe")
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
                raise RuntimeError("repository root changed or linked while opening")
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def private_tmp(root_fd: int) -> int:
    try:
        os.mkdir(".tmp", 0o700, dir_fd=root_fd)
    except FileExistsError:
        pass
    before = os.stat(".tmp", dir_fd=root_fd, follow_symlinks=False)
    descriptor = os.open(".tmp", DIRECTORY_FLAGS, dir_fd=root_fd)
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(before.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise RuntimeError("repository .tmp ownership, mode, or identity is unsafe")
    return descriptor


def acquire(tmp_fd: int) -> int:
    descriptor = os.open(
        "opswarden-e2e.lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=tmp_fd,
    )
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise RuntimeError("E2E lock file ownership or mode is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        print("E2E release gate refused: another run owns the OS lock", file=sys.stderr)
        raise SystemExit(75)
    os.set_inheritable(descriptor, False)
    return descriptor


def terminate_group(process: subprocess.Popen[bytes], first_signal: int) -> None:
    try:
        os.killpg(process.pid, first_signal)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def supervise(command: list[str]) -> int:
    process = subprocess.Popen(
        command,
        stdin=None,
        stdout=None,
        stderr=None,
        close_fds=True,
        start_new_session=True,
        env={
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "OPSWARDEN_E2E_LOCK_HELD",
                "MAKEFLAGS",
                "MFLAGS",
                "MAKELEVEL",
            }
        },
    )
    forwarded = 0
    signal_deadline: float | None = None

    def forward(received: int, _frame) -> None:
        nonlocal forwarded, signal_deadline
        if not forwarded:
            forwarded = received
            signal_deadline = time.monotonic() + 5
        try:
            os.killpg(process.pid, received)
        except ProcessLookupError:
            pass

    previous_int = signal.signal(signal.SIGINT, forward)
    previous_term = signal.signal(signal.SIGTERM, forward)
    try:
        while True:
            try:
                status = process.wait(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                if (
                    signal_deadline is not None
                    and time.monotonic() >= signal_deadline
                ):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    status = process.wait()
                    break
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)
    # A runner killed by PID can leave npm/node descendants alive. Reap the
    # process group before releasing the lock; normal completion is harmless.
    terminate_group(process, signal.SIGTERM)
    if forwarded:
        return 128 + forwarded
    if status < 0:
        return 128 - status
    return status


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] != "--":
        raise RuntimeError("usage: e2e_lock.py ABSOLUTE_REPO -- COMMAND [ARG ...]")
    repository = Path(argv[0])
    root_fd = open_absolute_directory(repository)
    tmp_fd = -1
    lock_fd = -1
    try:
        root = os.fstat(root_fd)
        if (
            root.st_uid != os.getuid()
            or not stat.S_ISDIR(root.st_mode)
            or stat.S_IMODE(root.st_mode) & 0o022
        ):
            raise RuntimeError("repository root ownership or mode is unsafe")
        tmp_fd = private_tmp(root_fd)
        lock_fd = acquire(tmp_fd)
        return supervise(argv[2:])
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if tmp_fd >= 0:
            os.close(tmp_fd)
        os.close(root_fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"E2E lock refused: {error}", file=sys.stderr)
        raise SystemExit(75)
