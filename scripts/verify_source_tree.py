#!/usr/bin/env python3
"""Require an exact clean commit before building the release-gate image."""

from __future__ import annotations

import os
import re
import subprocess
import sys


def git(*args: str) -> bytes:
    return subprocess.check_output(
        ["/usr/bin/git", *args],
        stderr=subprocess.DEVNULL,
        env={"HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=30,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 1 or re.fullmatch(r"[0-9a-f]{40}", argv[0]) is None:
        raise RuntimeError("a full lowercase SHA-1 revision is required")
    expected = argv[0].encode()
    if git("rev-parse", "--verify", "HEAD").strip() != expected:
        raise RuntimeError("release revision no longer matches HEAD")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("release gate refuses tracked or untracked source drift")
    if git("rev-parse", "--verify", f"{argv[0]}^{{commit}}").strip() != expected:
        raise RuntimeError("release revision is not a commit")
    print(f"release source verified: {argv[0]}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"release source refused: {error}", file=sys.stderr)
        raise SystemExit(2)
