from __future__ import annotations

import os

import pytest

from nessus_drata.state import (
    LastRunState,
    LockHeldError,
    acquire_lock,
    load_last_run_state,
    save_last_run_state,
)


def test_load_last_run_state_absent_file_returns_all_none(tmp_path):
    state = load_last_run_state(tmp_path)
    assert state == LastRunState()
    assert state.last_record_count is None


def test_save_then_load_round_trips(tmp_path):
    original = LastRunState(
        last_success_at="2026-08-18T11:00:03Z",
        last_record_count=100,
        last_session_id="nessus-47-20260818T041500Z",
        last_scan_ended_at="2026-08-18T04:15:00Z",
    )
    save_last_run_state(tmp_path, original)
    loaded = load_last_run_state(tmp_path)
    assert loaded == original


def test_load_last_run_state_corrupt_json_returns_all_none(tmp_path):
    (tmp_path / "last_run.json").write_text("{not valid json")
    state = load_last_run_state(tmp_path)
    assert state == LastRunState()


def test_acquire_lock_writes_and_removes_lock_file(tmp_path):
    lock_path = tmp_path / "collector.lock"
    assert not lock_path.exists()
    with acquire_lock(tmp_path):
        assert lock_path.exists()
        assert int(lock_path.read_text().strip()) == os.getpid()
    assert not lock_path.exists()


def test_acquire_lock_released_even_on_exception(tmp_path):
    lock_path = tmp_path / "collector.lock"
    with pytest.raises(RuntimeError):
        with acquire_lock(tmp_path):
            assert lock_path.exists()
            raise RuntimeError("boom")
    assert not lock_path.exists()


def test_acceptance_17_second_acquire_while_live_pid_holds_lock_raises():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        state_dir = Path(tmp)
        lock_path = state_dir / "collector.lock"
        lock_path.write_text(str(os.getpid()))

        with pytest.raises(LockHeldError):
            with acquire_lock(state_dir):
                pass  # pragma: no cover

        assert lock_path.exists()
        assert int(lock_path.read_text().strip()) == os.getpid()


def test_acceptance_18_dead_pid_lock_is_reclaimed(tmp_path):
    lock_path = tmp_path / "collector.lock"
    dead_pid = 999999
    lock_path.write_text(str(dead_pid))

    with acquire_lock(tmp_path):
        assert int(lock_path.read_text().strip()) == os.getpid()
    assert not lock_path.exists()


def test_windows_pid_liveness_treats_access_denied_as_running(monkeypatch):
    import ctypes
    import types

    import nessus_drata.state as state_module

    monkeypatch.setattr(state_module.sys, "platform", "win32")

    class FakeKernel32:
        def __init__(self, last_error):
            self._last_error = last_error

        def OpenProcess(self, *_args):
            return 0

        def GetLastError(self):
            return self._last_error

        def CloseHandle(self, _handle):
            pass

    ERROR_ACCESS_DENIED = 5
    ERROR_INVALID_PARAMETER = 87

    fake_windll_denied = types.SimpleNamespace(kernel32=FakeKernel32(ERROR_ACCESS_DENIED))
    monkeypatch.setattr(ctypes, "windll", fake_windll_denied, raising=False)
    assert state_module._pid_is_running(4242) is True

    fake_windll_other = types.SimpleNamespace(kernel32=FakeKernel32(ERROR_INVALID_PARAMETER))
    monkeypatch.setattr(ctypes, "windll", fake_windll_other, raising=False)
    assert state_module._pid_is_running(4242) is False
