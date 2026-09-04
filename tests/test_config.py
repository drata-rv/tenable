"""Acceptance tests 1-3: validate-config behavior. No network, no real credentials."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

DUMMY_ENV = {
    "NESSUS_ACCESS_KEY": "dummy-access-key-0001",
    "NESSUS_SECRET_KEY": "dummy-secret-key-9999",
    "DRATA_API_KEY": "dummy-drata-key-abcd",
}


def _run_cli(args, env_overrides=None, cwd=REPO_ROOT):
    import os

    env = os.environ.copy()
    env.update(DUMMY_ENV)
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, "-m", "nessus_drata.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def test_validate_config_example_exits_zero_no_secrets_leaked():
    result = _run_cli(
        [
            "--config",
            "config/config.example.yaml",
            "--checks",
            "config/checks.example.yaml",
            "validate-config",
        ]
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    for secret in DUMMY_ENV.values():
        assert secret not in combined
    assert "****0001" in result.stdout
    assert "****9999" in result.stdout
    assert "****abcd" in result.stdout


def test_validate_config_duplicate_field_exits_two(tmp_path):
    checks_path = tmp_path / "checks_dup.yaml"
    checks_path.write_text(
        """
schema_version: 1
audit_file: test.audit
checks:
  - field: dup_check_field
    label: "First"
    match:
      check_name_exact: "Check A"
    required: false
  - field: dup_check_field
    label: "Second"
    match:
      check_name_exact: "Check B"
    required: false
"""
    )
    result = _run_cli(
        [
            "--config",
            "config/config.example.yaml",
            "--checks",
            str(checks_path),
            "validate-config",
        ]
    )
    assert result.returncode == 2
    assert "dup_check_field" in result.stderr


def test_validate_config_reserved_name_exits_two(tmp_path):
    checks_path = tmp_path / "checks_reserved.yaml"
    checks_path.write_text(
        """
schema_version: 1
audit_file: test.audit
checks:
  - field: hostname
    label: "Reserved collision"
    match:
      check_name_exact: "Some check"
    required: false
"""
    )
    result = _run_cli(
        [
            "--config",
            "config/config.example.yaml",
            "--checks",
            str(checks_path),
            "validate-config",
        ]
    )
    assert result.returncode == 2
    assert "reserved" in result.stderr.lower()
    assert "hostname" in result.stderr


def test_validate_config_missing_env_var_exits_two(tmp_path):
    import os

    env = os.environ.copy()
    env.update(DUMMY_ENV)
    del env["DRATA_API_KEY"]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "nessus_drata.cli",
            "--config",
            "config/config.example.yaml",
            "--checks",
            "config/checks.example.yaml",
            "validate-config",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "DRATA_API_KEY" in result.stderr


def test_redact_masks_short_secrets_completely():
    """Review finding: redact() must not expose a secret whole just because
    it's 4 characters or shorter -- "last 4 characters" is only a partial
    mask when the secret is longer than that.
    """
    from nessus_drata.config import redact

    assert redact("") == "****"
    assert redact("a") == "****"
    assert redact("abcd") == "****"
    assert redact("abcde") == "****bcde"
    assert redact("a-real-looking-secret-key-12345") == "****2345"
