"""Pure predicate functions over the run summary and prior state (spec
Section 5.5). No side effects — no session cancellation, no logging, no I/O —
so every gate is a plain function and fully unit-testable in isolation. The
caller (cli.py's `run` command, later phase) is the only place that actually
acts on these results: cancelling a session, exiting 5, or (in dry-run mode)
just reporting them.

Gate order and names match spec Section 5.5's numbered list exactly:
  1. min_hosts
  2. max_shrink_ratio
  3. manifest_coverage
  4. duplicate_ids
  5. parse_mode
  6. batch_uploads
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

_FORCE_BYPASSABLE_GATES = frozenset({"min_hosts", "max_shrink_ratio"})


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    reason: str


def _gate_min_hosts(record_count: int, min_hosts: int) -> GateResult:
    passed = record_count >= min_hosts
    reason = (
        f"{record_count} record(s) >= min_hosts {min_hosts}"
        if passed
        else f"{record_count} record(s) is below min_hosts {min_hosts}"
    )
    return GateResult("min_hosts", passed, reason)


def _gate_max_shrink_ratio(
    record_count: int, previous_record_count: Optional[int], max_shrink_ratio: float
) -> GateResult:
    if previous_record_count is None:
        return GateResult(
            "max_shrink_ratio", True, "no prior run recorded — nothing to compare against"
        )
    threshold = previous_record_count * max_shrink_ratio
    passed = record_count >= threshold
    reason = (
        f"{record_count} >= {previous_record_count} * {max_shrink_ratio} ({threshold:.1f})"
        if passed
        else f"{record_count} is below {previous_record_count} * {max_shrink_ratio} ({threshold:.1f})"
    )
    return GateResult("max_shrink_ratio", passed, reason)


def _gate_manifest_coverage(coverage_pct: float, min_manifest_coverage_pct: float) -> GateResult:
    passed = coverage_pct >= min_manifest_coverage_pct
    reason = (
        f"coverage {coverage_pct:.1f}% >= min_manifest_coverage_pct {min_manifest_coverage_pct}%"
        if passed
        else f"coverage {coverage_pct:.1f}% is below min_manifest_coverage_pct {min_manifest_coverage_pct}%"
    )
    return GateResult("manifest_coverage", passed, reason)


def _gate_duplicate_ids(duplicate_ids: Sequence[str]) -> GateResult:
    passed = len(duplicate_ids) == 0
    reason = (
        "zero duplicate id values"
        if passed
        else f"duplicate id value(s): {', '.join(duplicate_ids)}"
    )
    return GateResult("duplicate_ids", passed, reason)


def _gate_parse_mode(parse_mode: str, allow_degraded_session: bool) -> GateResult:
    if parse_mode == "xml_full":
        return GateResult("parse_mode", True, "parse_mode is xml_full")
    if allow_degraded_session:
        return GateResult(
            "parse_mode",
            True,
            f"parse_mode is {parse_mode!r}, but --allow-degraded-session was passed",
        )
    return GateResult(
        "parse_mode",
        False,
        f"parse_mode is {parse_mode!r} and --allow-degraded-session was not passed",
    )


def _gate_batch_uploads(batch_upload_results: Optional[Sequence[bool]]) -> GateResult:
    if batch_upload_results is None:
        return GateResult(
            "batch_uploads", True, "not evaluated: no live upload attempted (dry-run)"
        )
    failed_count = sum(1 for ok in batch_upload_results if not ok)
    passed = failed_count == 0
    reason = (
        f"all {len(batch_upload_results)} batch(es) succeeded"
        if passed
        else f"{failed_count} of {len(batch_upload_results)} batch(es) failed"
    )
    return GateResult("batch_uploads", passed, reason)


def evaluate_gates(
    *,
    record_count: int,
    previous_record_count: Optional[int],
    coverage_pct: float,
    duplicate_ids: Sequence[str],
    parse_mode: str,
    allow_degraded_session: bool,
    batch_upload_results: Optional[Sequence[bool]],
    min_hosts: int,
    max_shrink_ratio: float,
    min_manifest_coverage_pct: float,
) -> tuple[GateResult, ...]:
    """Evaluate all 6 gates and return them in spec order, always. Never
    raises, never exits, never bypasses anything — see apply_force_bypass
    for --force handling.
    """
    return (
        _gate_min_hosts(record_count, min_hosts),
        _gate_max_shrink_ratio(record_count, previous_record_count, max_shrink_ratio),
        _gate_manifest_coverage(coverage_pct, min_manifest_coverage_pct),
        _gate_duplicate_ids(duplicate_ids),
        _gate_parse_mode(parse_mode, allow_degraded_session),
        _gate_batch_uploads(batch_upload_results),
    )


def apply_force_bypass(gates: Sequence[GateResult], force: bool) -> tuple[GateResult, ...]:
    """--force bypasses gates 1 and 2 ONLY (min_hosts, max_shrink_ratio),
    never 3 through 6. A bypassed gate is reported as passed with a reason
    naming the bypass, so the caller can log a prominent warning for each
    one it flips.
    """
    if not force:
        return tuple(gates)
    bypassed = []
    for gate in gates:
        if gate.name in _FORCE_BYPASSABLE_GATES and not gate.passed:
            bypassed.append(
                GateResult(
                    name=gate.name,
                    passed=True,
                    reason=f"BYPASSED by --force (was: {gate.reason})",
                )
            )
        else:
            bypassed.append(gate)
    return tuple(bypassed)


def bypassed_gate_names(gates: Sequence[GateResult]) -> tuple[str, ...]:
    """Names of gates whose reason indicates a --force bypass, for the
    caller to log a prominent warning naming each one (spec 5.5: "It must
    log a prominent warning naming each bypassed gate.")."""
    return tuple(g.name for g in gates if g.reason.startswith("BYPASSED by --force"))


def all_gates_passed(gates: Sequence[GateResult]) -> bool:
    return all(g.passed for g in gates)
