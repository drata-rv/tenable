"""Unit tests for state.py: last-run state persistence and the exclusive run
lock (spec Section 8). Covers acceptance tests 17 and 18 at the state-layer
level — the CLI-level "second invocation exits 6" behavior (test 17) is
wired in cli.py's `run` command and exercised end-to-end there; this file
proves the underlying lock primitive itself.
"""

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
    # Use this test process's own PID as the "live" holder — it's
    # definitely running for the duration of the test.
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        state_dir = Path(tmp)
        lock_path = state_dir / "collector.lock"
        lock_path.write_text(str(os.getpid()))

        with pytest.raises(LockHeldError):
            with acquire_lock(state_dir):
                pass  # pragma: no cover — should never get here

        # The held lock must be left untouched by the failed acquire.
        assert lock_path.exists()
        assert int(lock_path.read_text().strip()) == os.getpid()


def test_acceptance_18_dead_pid_lock_is_reclaimed(tmp_path):
    lock_path = tmp_path / "collector.lock"
    # PID 999999 is extremely unlikely to be a running process on any dev
    # or CI machine. If this ever flakes in a strange environment, that's
    # a sign the liveness check itself needs hardening, not this test.
    dead_pid = 999999
    lock_path.write_text(str(dead_pid))

    with acquire_lock(tmp_path):
        assert int(lock_path.read_text().strip()) == os.getpid()
    assert not lock_path.exists()
