#!/usr/bin/env python3
"""Offline emergency revocation with TTY-first input and verified UID drop."""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import sqlite3
import stat
import sys
import termios
from typing import Callable


DATABASE = Path("/srv/opswarden/state/data/opswarden.db")
OPSWARDEN_UID = 10001
OPSWARDEN_GID = 10001
PRIVATE_FILE_MODE = 0o600


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("offline revocation must start as root")


def read_hidden_line(tty_fd: int, prompt: bytes, limit: int = 512) -> bytearray:
    os.write(tty_fd, prompt)
    value = bytearray()
    while len(value) <= limit:
        chunk = os.read(tty_fd, 1)
        if not chunk:
            raise RuntimeError("TTY closed before input completed")
        if chunk in (b"\n", b"\r"):
            os.write(tty_fd, b"\n")
            return value
        value.extend(chunk)
    raise ValueError("hidden input exceeds maximum length")


def read_hidden_selection(
    tty_path: str = "/dev/tty", expected_owner_uid: int = 0
) -> tuple[bytearray, bytearray]:
    metadata = os.lstat(tty_path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISCHR(metadata.st_mode):
        raise PermissionError("interactive input must come from a character device")
    if metadata.st_uid != expected_owner_uid:
        raise PermissionError("interactive input device has an unexpected owner")
    tty_fd = os.open(
        tty_path,
        os.O_RDWR
        | getattr(os, "O_NOCTTY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    opened = os.fstat(tty_fd)
    if (
        not stat.S_ISCHR(opened.st_mode)
        or opened.st_uid != expected_owner_uid
        or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        os.close(tty_fd)
        raise PermissionError("interactive input device changed while opening")
    original = termios.tcgetattr(tty_fd)
    hidden = list(original)
    hidden[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(tty_fd, termios.TCSANOW, hidden)
        kind = read_hidden_line(tty_fd, b"revoke kind [user/agent] (hidden): ", 16)
        identifier = read_hidden_line(
            tty_fd, b"user email or exact agent id (hidden): "
        )
        return kind, identifier
    finally:
        termios.tcsetattr(tty_fd, termios.TCSANOW, original)
        os.close(tty_fd)


def drop_privileges(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if (
        os.getuid() != uid
        or os.geteuid() != uid
        or os.getgid() != gid
        or os.getegid() != gid
        or os.getgroups()
    ):
        raise PermissionError("privilege drop verification failed")


def open_database(path: Path, expected_uid: int, expected_gid: int):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("database path must be absolute")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("database must be a regular non-symlink file")
    if metadata.st_size <= 0 or path.resolve(strict=True) != path:
        raise ValueError("database must be nonempty and canonical")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise PermissionError("database ownership does not match dropped identity")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
        raise PermissionError("database mode must be 0600")
    connection = sqlite3.connect(
        f"file:{path}?mode=rw", uri=True, isolation_level=None, timeout=5.0
    )
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
    except BaseException:
        connection.close()
        raise
    if integrity != [("ok",)]:
        connection.close()
        raise RuntimeError("database integrity_check did not return exact ok")
    opened = os.lstat(path)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        connection.close()
        raise PermissionError("database changed while opening")
    return connection


def wipe(value: bytearray | None) -> None:
    if value is not None:
        for index in range(len(value)):
            value[index] = 0


def revoke_active(
    connection: sqlite3.Connection, kind: bytearray, identifier: bytearray
) -> int:
    kind_text = kind.decode("ascii", errors="strict")
    identifier_text = identifier.decode("utf-8", errors="strict").strip()
    if not identifier_text or len(identifier_text.encode("utf-8")) > 512:
        raise ValueError("invalid revocation selector")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    connection.execute("BEGIN IMMEDIATE")
    try:
        if kind_text == "user":
            normalized_identifier = identifier_text.lower()
            expected = connection.execute(
                """
                SELECT COUNT(*)
                  FROM sessions s
                  JOIN users u ON u.id = s.user_id
                 WHERE u.normalized_email = ?
                   AND s.revoked_at IS NULL
                """,
                (normalized_identifier,),
            ).fetchone()[0]
            if expected <= 0:
                raise RuntimeError("no active rows matched")
            cursor = connection.execute(
                """
                UPDATE sessions
                   SET revoked_at = ?
                 WHERE user_id = (
                     SELECT id FROM users
                      WHERE normalized_email = ?
                 )
                   AND revoked_at IS NULL
                """,
                (now, normalized_identifier),
            )
        elif kind_text == "agent":
            expected = connection.execute(
                """
                SELECT COUNT(*) FROM agent_tokens
                 WHERE agent_id = ? AND revoked_at IS NULL
                """,
                (identifier_text,),
            ).fetchone()[0]
            if expected <= 0:
                raise RuntimeError("no active rows matched")
            cursor = connection.execute(
                """
                UPDATE agent_tokens SET revoked_at = ?
                 WHERE agent_id = ? AND revoked_at IS NULL
                """,
                (now, identifier_text),
            )
        else:
            raise ValueError("invalid revoke kind")
        if cursor.rowcount != expected:
            raise RuntimeError("active row count changed during revocation")
        connection.commit()
        return expected
    except BaseException:
        connection.rollback()
        raise
    finally:
        identifier_text = None


def orchestrate(
    database: Path = DATABASE,
    uid: int = OPSWARDEN_UID,
    gid: int = OPSWARDEN_GID,
    require_root_fn: Callable[[], None] = require_root,
    read_selection_fn: Callable[[], tuple[bytearray, bytearray]] = read_hidden_selection,
    drop_privileges_fn: Callable[[int, int], None] = drop_privileges,
    open_database_fn: Callable[[Path, int, int], sqlite3.Connection] = open_database,
    revoke_fn: Callable[[sqlite3.Connection, bytearray, bytearray], int] = revoke_active,
) -> int:
    kind = None
    identifier = None
    connection = None
    require_root_fn()
    try:
        kind, identifier = read_selection_fn()
        drop_privileges_fn(uid, gid)
        connection = open_database_fn(database, uid, gid)
        return revoke_fn(connection, kind, identifier)
    finally:
        if connection is not None:
            connection.close()
        wipe(kind)
        wipe(identifier)
        kind = None
        identifier = None


def main() -> int:
    try:
        count = orchestrate()
    except (OSError, RuntimeError, UnicodeError, ValueError, sqlite3.Error) as error:
        print(f"offline revocation refused: {error}", file=sys.stderr)
        return 1
    print(f"revoked active rows: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
