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


def _gate_manifest_coverage(
    coverage_pct: float,
    min_manifest_coverage_pct: float,
    no_results_reason: Optional[str],
) -> GateResult:
    if no_results_reason:
        return GateResult("manifest_coverage", False, f"NO RESULTS: {no_results_reason}")
    if coverage_pct < min_manifest_coverage_pct:
        return GateResult(
            "manifest_coverage",
            True,
            f"coverage {coverage_pct:.1f}% is below min_manifest_coverage_pct "
            f"{min_manifest_coverage_pct}%: pushing anyway, missing checks recorded as NOT_FOUND",
        )
    return GateResult(
        "manifest_coverage",
        True,
        f"coverage {coverage_pct:.1f}% >= min_manifest_coverage_pct {min_manifest_coverage_pct}%",
    )


def _gate_duplicate_ids(duplicate_ids: Sequence[str]) -> GateResult:
    passed = len(duplicate_ids) == 0
    reason = (
        "zero duplicate id values"
        if passed
        else f"duplicate id value(s): {', '.join(duplicate_ids)}"
    )
    return GateResult("duplicate_ids", passed, reason)


def _gate_batch_uploads(batch_upload_results: Optional[Sequence[bool]]) -> GateResult:
    if batch_upload_results is None:
        return GateResult(
            "batch_uploads",
            True,
            "not evaluated: no upload attempted (dry-run, or an earlier gate failed first)",
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
    batch_upload_results: Optional[Sequence[bool]],
    min_hosts: int,
    max_shrink_ratio: float,
    min_manifest_coverage_pct: float,
    no_results_reason: Optional[str] = None,
) -> tuple[GateResult, ...]:
    return (
        _gate_min_hosts(record_count, min_hosts),
        _gate_max_shrink_ratio(record_count, previous_record_count, max_shrink_ratio),
        _gate_manifest_coverage(coverage_pct, min_manifest_coverage_pct, no_results_reason),
        _gate_duplicate_ids(duplicate_ids),
        _gate_batch_uploads(batch_upload_results),
    )


def apply_force_bypass(gates: Sequence[GateResult], force: bool) -> tuple[GateResult, ...]:
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
    return tuple(g.name for g in gates if g.reason.startswith("BYPASSED by --force"))


def all_gates_passed(gates: Sequence[GateResult]) -> bool:
    return all(g.passed for g in gates)
