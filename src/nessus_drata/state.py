"""Last-run state and an exclusive run lock (spec Section 8).

A hard reboot must not wedge the schedule permanently: a lock file whose PID
is no longer running is stale and gets reclaimed automatically rather than
requiring manual cleanup on a Windows box nobody is watching.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, Optional

STATE_FILENAME = "last_run.json"
LOCK_FILENAME = "collector.lock"


class LockHeldError(Exception):
    """Raised when another live process holds the run lock. Maps to exit
    code 6 in the CLI."""


@dataclass(frozen=True)
class LastRunState:
    last_success_at: Optional[str] = None
    last_record_count: Optional[int] = None
    last_session_id: Optional[str] = None
    last_scan_ended_at: Optional[str] = None


def load_last_run_state(state_dir: Path) -> LastRunState:
    """Returns an all-None state if no prior run is recorded — a first run
    has nothing to compare against, which is exactly what safety gate 2
    (shrink-ratio) needs to know to pass trivially.
    """
    path = Path(state_dir) / STATE_FILENAME
    if not path.exists():
        return LastRunState()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return LastRunState()
    return LastRunState(
        last_success_at=data.get("last_success_at"),
        last_record_count=data.get("last_record_count"),
        last_session_id=data.get("last_session_id"),
        last_scan_ended_at=data.get("last_scan_ended_at"),
    )


def save_last_run_state(state_dir: Path, state: LastRunState) -> None:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / STATE_FILENAME
    path.write_text(json.dumps(asdict(state), indent=2) + "\n")


def _pid_is_running(pid: int) -> bool:
    """Cross-platform liveness check with no extra dependency (psutil is not
    in the allowed dependency list). The production target is Windows, but
    this also needs to work correctly on POSIX dev/CI machines.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by another user
    return True


@contextmanager
def acquire_lock(state_dir: Path) -> Iterator[None]:
    """Exclusive run lock at state_dir/collector.lock containing the holder's
    PID. Raises LockHeldError if a live process holds it. A lock whose PID
    is no longer running is treated as stale and silently reclaimed.
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / LOCK_FILENAME

    if lock_path.exists():
        held_pid: Optional[int] = None
        try:
            held_pid = int(lock_path.read_text().strip())
        except (ValueError, OSError):
            held_pid = None
        if held_pid is not None and _pid_is_running(held_pid):
            raise LockHeldError(
                f"lock held by running process {held_pid}: {lock_path}"
            )
        # Stale lock (dead PID, or unreadable/corrupt lock file) — reclaim.

    lock_path.write_text(str(os.getpid()))
    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
