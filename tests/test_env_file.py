"""The .env loader: parsing, precedence, and the CLI wiring. No network."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nessus_drata.config import REQUIRED_ENV_VARS, ConfigError, load_env_file, parse_env_text

REPO_ROOT = Path(__file__).resolve().parents[1]

ACCESS = "access-from-dotenv-1111"
SECRET = "secret-from-dotenv-2222"
DRATA = "drata-from-dotenv-3333"


def test_parse_env_text_forms():
    text = (
        "# comment\n"
        "\n"
        "NESSUS_ACCESS_KEY=abc123\n"
        "export NESSUS_SECRET_KEY = \"quoted value\"  # trailing comment\n"
        "DRATA_API_KEY='single'\n"
        "OTHER=plain value # inline comment\n"
        "not a pair\n"
        "CRLF_KEY=with-crlf\r\n"
    )
    values, bad = parse_env_text(text)
    assert values["NESSUS_ACCESS_KEY"] == "abc123"
    assert values["NESSUS_SECRET_KEY"] == "quoted value"
    assert values["DRATA_API_KEY"] == "single"
    assert values["OTHER"] == "plain value"
    assert values["CRLF_KEY"] == "with-crlf"
    assert bad == [7]


def test_parse_env_text_hash_inside_value_without_space_is_kept():
    values, _ = parse_env_text("DRATA_API_KEY=ab#cd\n")
    assert values["DRATA_API_KEY"] == "ab#cd"


@pytest.fixture
def clean_env(monkeypatch):
    for name in REQUIRED_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_load_sets_the_three_secrets_and_handles_bom(tmp_path, clean_env):
    env_file = tmp_path / ".env"
    env_file.write_bytes(
        "﻿NESSUS_ACCESS_KEY={}\nNESSUS_SECRET_KEY={}\nDRATA_API_KEY={}\n".format(
            ACCESS, SECRET, DRATA
        ).encode("utf-8")
    )
    loaded = load_env_file(env_file)
    assert loaded == list(REQUIRED_ENV_VARS)
    assert os.environ["NESSUS_ACCESS_KEY"] == ACCESS
    assert os.environ["NESSUS_SECRET_KEY"] == SECRET
    assert os.environ["DRATA_API_KEY"] == DRATA


def test_real_environment_wins_over_file(tmp_path, clean_env):
    clean_env.setenv("NESSUS_ACCESS_KEY", "from-real-env")
    env_file = tmp_path / ".env"
    env_file.write_text(f"NESSUS_ACCESS_KEY={ACCESS}\nNESSUS_SECRET_KEY={SECRET}\n")
    loaded = load_env_file(env_file)
    assert os.environ["NESSUS_ACCESS_KEY"] == "from-real-env"
    assert os.environ["NESSUS_SECRET_KEY"] == SECRET
    assert loaded == ["NESSUS_SECRET_KEY"]


def test_blank_values_are_ignored(tmp_path, clean_env):
    env_file = tmp_path / ".env"
    env_file.write_text("NESSUS_ACCESS_KEY=\nNESSUS_SECRET_KEY=   \nDRATA_API_KEY=\"\"\n")
    assert load_env_file(env_file) == []
    for name in REQUIRED_ENV_VARS:
        assert name not in os.environ


def test_unrecognized_keys_never_reach_the_environment(tmp_path, clean_env, caplog):
    clean_env.delenv("PYTHONPATH", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("PYTHONPATH=/evil\nNESSUS_ACESS_KEY=typo-secret-9999\n")
    with caplog.at_level("WARNING", logger="nessus_drata.config"):
        assert load_env_file(env_file) == []
    assert "PYTHONPATH" not in os.environ
    assert "NESSUS_ACESS_KEY" in caplog.text
    assert "typo-secret-9999" not in caplog.text
    assert "/evil" not in caplog.text


def test_malformed_line_warning_never_echoes_content(tmp_path, clean_env, caplog):
    env_file = tmp_path / ".env"
    env_file.write_text("NESSUS_ACCESS_KEY: 11d3f7132bbb7bce\n")
    with caplog.at_level("WARNING", logger="nessus_drata.config"):
        load_env_file(env_file)
    assert "line(s) 1" in caplog.text
    assert "11d3f7132bbb7bce" not in caplog.text


def test_missing_file_ok_unless_required(tmp_path, clean_env):
    assert load_env_file(tmp_path / "nope.env") == []
    with pytest.raises(ConfigError, match="env file not found"):
        load_env_file(tmp_path / "nope.env", required=True)


# ---- CLI wiring -----------------------------------------------------------


def _stripped_env():
    env = os.environ.copy()
    for name in REQUIRED_ENV_VARS:
        env.pop(name, None)
    return env


def _cli(args, cwd, env):
    return subprocess.run(
        [sys.executable, "-m", "nessus_drata.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture
def cfg_dir(tmp_path):
    d = tmp_path / "config"
    d.mkdir()
    shutil.copy(REPO_ROOT / "config" / "config.example.yaml", d / "config.yaml")
    shutil.copy(REPO_ROOT / "config" / "checks.example.yaml", d / "checks.yaml")
    return d


def _validate(cfg_dir, cwd, env, *extra):
    return _cli(
        [
            "--config", str(cfg_dir / "config.yaml"),
            "--checks", str(cfg_dir / "checks.yaml"),
            *extra,
            "validate-config",
        ],
        cwd,
        env,
    )


def test_cli_loads_dotenv_next_to_config(cfg_dir, tmp_path):
    (cfg_dir / ".env").write_text(
        f"NESSUS_ACCESS_KEY={ACCESS}\nNESSUS_SECRET_KEY={SECRET}\nDRATA_API_KEY={DRATA}\n"
    )
    result = _validate(cfg_dir, tmp_path, _stripped_env())
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    for secret in (ACCESS, SECRET, DRATA):
        assert secret not in combined
    assert "****1111" in result.stdout
    assert "****2222" in result.stdout
    assert "****3333" in result.stdout


def test_cli_loads_dotenv_from_working_directory(cfg_dir, tmp_path):
    (tmp_path / ".env").write_text(
        f"NESSUS_ACCESS_KEY={ACCESS}\nNESSUS_SECRET_KEY={SECRET}\nDRATA_API_KEY={DRATA}\n"
    )
    result = _validate(cfg_dir, tmp_path, _stripped_env())
    assert result.returncode == 0, result.stderr


def test_cli_explicit_env_file_and_real_env_precedence(cfg_dir, tmp_path):
    custom = tmp_path / "elsewhere.env"
    custom.write_text(
        f"NESSUS_ACCESS_KEY={ACCESS}\nNESSUS_SECRET_KEY={SECRET}\nDRATA_API_KEY={DRATA}\n"
    )
    env = _stripped_env()
    env["DRATA_API_KEY"] = "real-env-drata-7777"
    result = _validate(cfg_dir, tmp_path, env, "--env-file", str(custom))
    assert result.returncode == 0, result.stderr
    assert "****1111" in result.stdout
    assert "****7777" in result.stdout  # real env var beat the file
    assert "****3333" not in result.stdout


def test_cli_explicit_env_file_missing_exits_two(cfg_dir, tmp_path):
    result = _validate(cfg_dir, tmp_path, _stripped_env(), "--env-file", str(tmp_path / "gone.env"))
    assert result.returncode == 2
    assert "env file not found" in result.stderr


def test_cli_no_env_anywhere_exits_two_and_points_at_dotenv(cfg_dir, tmp_path):
    result = _validate(cfg_dir, tmp_path, _stripped_env())
    assert result.returncode == 2
    assert ".env" in result.stderr
