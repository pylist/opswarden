#!/usr/bin/env python3
"""Run a command with bounded output, time, and TERM-to-KILL shutdown."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time

MAX_OUTPUT = 4 << 20


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise RuntimeError("usage: bounded_command.py TIMEOUT ABSOLUTE_COMMAND [ARG ...]")
    timeout = int(argv[0])
    command = argv[1:]
    if timeout < 1 or timeout > 60 or not os.path.isabs(command[0]):
        raise RuntimeError("bounded command arguments are unsafe")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, True)
    selector.register(process.stderr, selectors.EVENT_READ, False)
    stdout_chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout

    def stop() -> None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop()
            raise RuntimeError("bounded command timed out")
        events = selector.select(min(remaining, 0.25))
        for key, _ in events:
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            total += len(chunk)
            if total > MAX_OUTPUT:
                stop()
                raise RuntimeError("bounded command output exceeded limit")
            if key.data:
                stdout_chunks.append(chunk)
    try:
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        stop()
        raise RuntimeError("bounded command timed out")
    if process.returncode != 0:
        raise RuntimeError(f"bounded command failed with status {process.returncode}")
    for chunk in stdout_chunks:
        os.write(sys.stdout.fileno(), chunk)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"bounded command refused: {error}", file=sys.stderr)
        raise SystemExit(2)
