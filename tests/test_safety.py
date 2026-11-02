from __future__ import annotations

from nessus_drata.safety import (
    all_gates_passed,
    apply_force_bypass,
    bypassed_gate_names,
    evaluate_gates,
)

_DEFAULTS = dict(
    min_hosts=50,
    max_shrink_ratio=0.8,
    min_manifest_coverage_pct=90,
)


_NO_RESULTS = "the scan result has no hosts"


def _gates(**overrides):
    kwargs = dict(
        record_count=100,
        previous_record_count=None,
        coverage_pct=100.0,
        duplicate_ids=(),
        batch_upload_results=None,
        **_DEFAULTS,
    )
    kwargs.update(overrides)
    return evaluate_gates(**kwargs)


def test_all_gates_pass_on_healthy_run():
    gates = _gates()
    assert all_gates_passed(gates)
    assert [g.name for g in gates] == [
        "min_hosts",
        "max_shrink_ratio",
        "manifest_coverage",
        "duplicate_ids",
        "batch_uploads",
    ]


def test_acceptance_10_min_hosts_gate_fails_below_threshold():
    gates = _gates(record_count=10)
    assert not all_gates_passed(gates)
    min_hosts_gate = next(g for g in gates if g.name == "min_hosts")
    assert min_hosts_gate.passed is False
    assert "10" in min_hosts_gate.reason and "50" in min_hosts_gate.reason


def test_acceptance_11_shrink_ratio_gate_fails_on_sudden_drop():
    gates = _gates(record_count=60, previous_record_count=100)
    assert not all_gates_passed(gates)
    shrink_gate = next(g for g in gates if g.name == "max_shrink_ratio")
    assert shrink_gate.passed is False
    assert "60" in shrink_gate.reason


def test_shrink_ratio_gate_passes_with_no_prior_state():
    gates = _gates(record_count=5, previous_record_count=None)
    shrink_gate = next(g for g in gates if g.name == "max_shrink_ratio")
    assert shrink_gate.passed is True
    assert "no prior run" in shrink_gate.reason


def test_acceptance_12_force_bypasses_only_gates_1_and_2():
    gates = _gates(record_count=60, previous_record_count=100, no_results_reason=_NO_RESULTS)
    assert not all_gates_passed(gates)

    forced = apply_force_bypass(gates, force=True)
    by_name = {g.name: g for g in forced}

    assert by_name["max_shrink_ratio"].passed is True
    assert "BYPASSED by --force" in by_name["max_shrink_ratio"].reason

    assert by_name["manifest_coverage"].passed is False
    assert not all_gates_passed(forced)

    assert bypassed_gate_names(forced) == ("max_shrink_ratio",)


def test_force_false_does_not_change_anything():
    gates = _gates(record_count=10)
    not_forced = apply_force_bypass(gates, force=False)
    assert not_forced == gates


def test_force_never_bypasses_gates_3_through_5():
    gates = _gates(
        record_count=10,
        previous_record_count=100,
        coverage_pct=0.0,
        no_results_reason=_NO_RESULTS,
        duplicate_ids=("nessus-dup",),
        batch_upload_results=[True, False],
    )
    forced = apply_force_bypass(gates, force=True)
    by_name = {g.name: g for g in forced}

    assert by_name["min_hosts"].passed is True
    assert by_name["max_shrink_ratio"].passed is True
    assert by_name["manifest_coverage"].passed is False
    assert by_name["duplicate_ids"].passed is False
    assert by_name["batch_uploads"].passed is False
    assert set(bypassed_gate_names(forced)) == {"min_hosts", "max_shrink_ratio"}


def test_duplicate_ids_gate():
    gates = _gates(duplicate_ids=("nessus-wks-0001",))
    dup_gate = next(g for g in gates if g.name == "duplicate_ids")
    assert dup_gate.passed is False
    assert "nessus-wks-0001" in dup_gate.reason


def test_manifest_coverage_gate_passes_at_or_above_threshold():
    coverage_gate = next(g for g in _gates(coverage_pct=90.0) if g.name == "manifest_coverage")
    assert coverage_gate.passed is True
    assert "NOT_FOUND" not in coverage_gate.reason


def test_manifest_coverage_gate_pushes_partial_coverage_and_says_so():
    gates = _gates(coverage_pct=40.0)
    coverage_gate = next(g for g in gates if g.name == "manifest_coverage")
    assert coverage_gate.passed is True
    assert "NOT_FOUND" in coverage_gate.reason
    assert all_gates_passed(gates)


def test_manifest_coverage_gate_fails_with_no_results_reason():
    gates = _gates(coverage_pct=100.0, no_results_reason=_NO_RESULTS)
    coverage_gate = next(g for g in gates if g.name == "manifest_coverage")
    assert coverage_gate.passed is False
    assert coverage_gate.reason == f"NO RESULTS: {_NO_RESULTS}"
    assert not all_gates_passed(gates)


def test_batch_uploads_gate_none_means_not_evaluated():
    gates = _gates(batch_upload_results=None)
    batch_gate = next(g for g in gates if g.name == "batch_uploads")
    assert batch_gate.passed is True
    assert "not evaluated" in batch_gate.reason


def test_batch_uploads_gate_fails_on_any_failed_batch():
    gates = _gates(batch_upload_results=[True, True, False])
    batch_gate = next(g for g in gates if g.name == "batch_uploads")
    assert batch_gate.passed is False
