"""Small cross-process locks and durable atomic state-file writes."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Iterator


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def lock_path(path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    return target.with_suffix(target.suffix + ".lock")


def _process_lock(handle: object, lock: bool) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        mode = msvcrt.LK_NBLCK if lock else msvcrt.LK_UNLCK
        msvcrt.locking(handle.fileno(), mode, 1)
    else:
        import fcntl
        mode = fcntl.LOCK_EX | fcntl.LOCK_NB if lock else fcntl.LOCK_UN
        fcntl.flock(handle.fileno(), mode)


@contextmanager
def exclusive_path_lock(path: str | Path, timeout: float = 30.0) -> Iterator[None]:
    """Lock one state family across threads and processes."""
    lockfile = lock_path(path)
    key = str(lockfile)
    with _LOCKS_GUARD:
        thread_lock = _LOCKS.setdefault(key, threading.Lock())
    if not thread_lock.acquire(timeout=timeout):
        raise TimeoutError(f"state lock timed out: {lockfile}")
    handle = None
    try:
        lockfile.parent.mkdir(parents=True, exist_ok=True)
        handle = lockfile.open("a+b")
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                _process_lock(handle, True)
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"state lock timed out: {lockfile}") from error
                time.sleep(0.02)
        try:
            yield
        finally:
            _process_lock(handle, False)
    finally:
        if handle is not None:
            handle.close()
        thread_lock.release()


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: str | Path, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        _sync_directory(target.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: str | Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def durable_unlink(path: str | Path) -> None:
    target = Path(path)
    try:
        target.unlink()
    except FileNotFoundError:
        return
    _sync_directory(target.parent)
