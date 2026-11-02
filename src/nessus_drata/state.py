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
    pass


@dataclass(frozen=True)
class LastRunState:
    last_success_at: Optional[str] = None
    last_record_count: Optional[int] = None
    last_session_id: Optional[str] = None
    last_scan_ended_at: Optional[str] = None


def load_last_run_state(state_dir: Path) -> LastRunState:
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
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        ERROR_ACCESS_DENIED = 5
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        if ctypes.windll.kernel32.GetLastError() == ERROR_ACCESS_DENIED:
            return True
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@contextmanager
def acquire_lock(state_dir: Path) -> Iterator[None]:
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

    lock_path.write_text(str(os.getpid()))
    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
