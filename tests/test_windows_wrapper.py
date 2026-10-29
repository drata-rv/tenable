"""windows/run_collector.cmd must hand argparse an argv it accepts, and must
propagate the collector's exit code (spec 9.3)."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from nessus_drata.cli import build_parser

WRAPPER = Path(__file__).resolve().parents[1] / "windows" / "run_collector.cmd"


def _collector_argv() -> list[str]:
    text = WRAPPER.read_text()
    # Join "^" line continuations, then take the interpreter invocation.
    joined = re.sub(r"\^\s*\r?\n\s*", " ", text)
    line = next(l for l in joined.splitlines() if "-m nessus_drata.cli" in l)
    after = line.split("-m nessus_drata.cli", 1)[1]
    return shlex.split(after, posix=False)


def test_wrapper_argv_is_accepted_by_the_real_parser():
    argv = [a.strip('"') for a in _collector_argv()]
    args = build_parser().parse_args(argv)
    assert args.command == "run"
    assert args.config.endswith("config.yaml")
    assert args.checks.endswith("checks.yaml")
    assert args.log_level == "INFO"


def test_wrapper_propagates_exit_code():
    text = WRAPPER.read_text()
    assert 'set "RC=%ERRORLEVEL%"' in text
    assert text.rstrip().endswith("exit /b %RC%")
