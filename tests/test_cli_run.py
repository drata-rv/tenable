"""CLI-level integration tests for the `run` command (acceptance tests 9
(dry-run payload half), 17, 18 at the CLI boundary, plus the Phase 4 stop
condition itself: --dry-run writes valid payloads, zero network calls, zero
credentials required when --fixtures is given).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = "tests/fixtures/config_offline.yaml"
CHECKS = "tests/fixtures/checks_small.yaml"
FIXTURE = "tests/fixtures/sample_small.nessus"


def _run_cli(args, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "nessus_drata.cli", *args],
        cwd=cwd or REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _no_credentials_env(tmp_path_str: str = None):
    env = os.environ.copy()
    for key in ("NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY", "DRATA_API_KEY"):
        env.pop(key, None)
    return env


def test_dry_run_with_fixtures_requires_zero_credentials(tmp_path):
    env = _no_credentials_env()
    result = _run_cli(
        [
            "--config",
            CONFIG,
            "--checks",
            CHECKS,
            "run",
            "--fixtures",
            FIXTURE,
            "--dry-run",
        ],
        env=env,
        cwd=tmp_path,
    )
    # cwd=tmp_path so relative artifacts/state/log dirs land in an isolated
    # scratch directory, not the real repo tree — but --config/--checks
    # paths are relative to REPO_ROOT, so pass absolute paths instead.
    assert result.returncode != 127, result.stderr  # sanity: module resolvable

    # Re-run with absolute config/checks paths against the isolated tmp cwd.
    result = _run_cli(
        [
            "--config",
            str(REPO_ROOT / CONFIG),
            "--checks",
            str(REPO_ROOT / CHECKS),
            "run",
            "--fixtures",
            str(REPO_ROOT / FIXTURE),
            "--dry-run",
        ],
        env=env,
        cwd=tmp_path,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "exit_code=0" in result.stdout

    payloads_root = tmp_path / "artifacts" / "payloads"
    assert payloads_root.exists()
    run_dirs = list(payloads_root.iterdir())
    assert len(run_dirs) == 1
    records_path = run_dirs[0] / "records.json"
    assert records_path.exists()
    records = json.loads(records_path.read_text())
    assert len(records) == 3
    assert all("id" in r and "hostname" in r for r in records)

    report_files = list((tmp_path / "artifacts" / "reports").iterdir())
    assert len(report_files) == 1
    report = json.loads(report_files[0].read_text())
    assert report["parse_mode"] == "xml_full"
    assert report["exit_code"] == 0
    gate_names = {g["name"] for g in report["safety_gates"]}
    assert gate_names == {
        "min_hosts",
        "max_shrink_ratio",
        "manifest_coverage",
        "duplicate_ids",
        "parse_mode",
        "batch_uploads",
    }


def test_run_without_fixtures_and_without_credentials_exits_config_error(tmp_path):
    env = _no_credentials_env()
    result = _run_cli(
        [
            "--config",
            str(REPO_ROOT / CONFIG),
            "--checks",
            str(REPO_ROOT / CHECKS),
            "run",
            "--dry-run",
        ],
        env=env,
        cwd=tmp_path,
    )
    assert result.returncode == 2
    assert "NESSUS_ACCESS_KEY" in result.stderr


def test_acceptance_17_second_run_while_lock_held_exits_six(tmp_path):
    env = os.environ.copy()
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "collector.lock").write_text(str(os.getpid()))

    result = _run_cli(
        [
            "--config",
            str(REPO_ROOT / CONFIG),
            "--checks",
            str(REPO_ROOT / CHECKS),
            "run",
            "--fixtures",
            str(REPO_ROOT / FIXTURE),
            "--dry-run",
        ],
        env=env,
        cwd=tmp_path,
    )
    assert result.returncode == 6
    assert "lock held" in result.stderr.lower()

    # No payloads should have been written — the lock check happens before
    # any pipeline work.
    assert not (tmp_path / "artifacts" / "payloads").exists()


def test_acceptance_18_dead_pid_lock_is_reclaimed_by_cli(tmp_path):
    env = os.environ.copy()
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "collector.lock").write_text("999999")

    result = _run_cli(
        [
            "--config",
            str(REPO_ROOT / CONFIG),
            "--checks",
            str(REPO_ROOT / CHECKS),
            "run",
            "--fixtures",
            str(REPO_ROOT / FIXTURE),
            "--dry-run",
        ],
        env=env,
        cwd=tmp_path,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
